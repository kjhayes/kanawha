
#include <kanawha/assert.h>
#include <kanawha/errno.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/printk.h>
#include <kanawha/scheduler.h>
#include <kanawha/stddef.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>
#include <kanawha/waitqueue.h>

// #define ENFORCE_NAME_ALL_WAITQUEUES

int
waitqueue_init(struct waitqueue *queue)
{
    irq_lock_init(&queue->lock);
    queue->flags = 0;
    queue->num_threads = 0;
    ilist_init(&queue->waiting_threads);
    queue->dyn_name = 0;
    queue->name = "unnamed-waitqueue";
    return 0;
}

int
waitqueue_name(struct waitqueue *queue, const char *to_copy)
{
    char *name = kstrdup(to_copy);
    if(name == NULL)
    {
        return -ENOMEM;
    }

    irq_lock_acquire(&queue->lock);
    if(queue->dyn_name)
    {
        char *old_name = queue->name;
        queue->name = name;
        mbarrier();
        kfree(old_name);
    }
    else
    {
        queue->dyn_name = 1;
        queue->name = name;
    }
    irq_lock_release(&queue->lock);
    return 0;
}

int
waitqueue_deinit(struct waitqueue *queue)
{
    waitqueue_disable(queue);
    while(1)
    {
        wake_all(queue);
        irq_lock_acquire(&queue->lock);
        if(queue->num_threads == 0)
        {
            irq_lock_release(&queue->lock);
            break;
        }
        irq_lock_release(&queue->lock);
        pause();
    }

    irq_lock_acquire(&queue->lock);
    if(queue->dyn_name)
    {
        kfree(queue->name);
        // Do this to help with debugging
#ifdef CONFIG_DEBUGGING
        queue->name = "destroyed-waitqueue";
#else
        queue->name = NULL
#endif // CONFIG_DEBUGGING
        queue->dyn_name = 0;
    }
    irq_lock_release(&queue->lock);

    return 0;
}

int
wait_on_with_callback(struct waitqueue *queue,
                      wait_on_callback_f *callback,
                      void *priv_state)
{
    int res;

    struct thread_state *cur = current_thread();

    irq_lock_acquire(&queue->lock);

    if(queue->flags & WAITQUEUE_DISABLED)
    {
        irq_lock_release(&queue->lock);
        return 0; // Should this be an error?
                  // ehhhhhhhhhhhhh... idk -KJH
    }

    // (Instead of going from RUNNING -> READY we will
    //  go from TIRED -> SLEEPING on next thread_switch)
    res = thread_tire(cur);
    if(res)
    {
        irq_lock_release(&queue->lock);
        return res;
    }

    // Place ourself onto the waitqueue
    ilist_push_tail(&queue->waiting_threads, &cur->waitqueue_node);
    cur->waitqueue = queue;
    queue->num_threads++;

    // Unlock the queue
    irq_lock_release(&queue->lock);

    if(callback != NULL)
    {
        (*callback)(priv_state);
    }

    // Force a reschedule (TIRED -> SLEEPING)
    hard_resched();
    thread_switch();

    // We're back! (a "wake_*" function should have
    // removed us from the queue already)

    // Make sure that we haven't woken up spurriously
    irq_lock_acquire(&queue->lock);

#ifdef ENFORCE_NAME_ALL_WAITQUEUES
    if(strcmp(queue->name, "unnamed-waitqueue") == 0)
    {
        panic("Waiting on an unnamed waitqueue!\n");
    }
#endif

    if(cur->waitqueue == queue)
    {
        // Something interrupted us (probably a signal)
        queue->num_threads--;
        ilist_remove(&queue->waiting_threads, &cur->waitqueue_node);
        cur->waitqueue = NULL;
        irq_lock_release(&queue->lock);
        return -EINTR;
    }
    irq_lock_release(&queue->lock);

    return 0;
}

int
wait_on(struct waitqueue *queue)
{
    return wait_on_with_callback(queue, NULL, NULL);
}

static void
wait_on_spin_unlock_callback(void *__lock)
{
    spinlock_t *lock = __lock;
    spin_unlock(lock);
}
static void
wait_on_thread_lock_release_callback(void *__lock)
{
    struct thread_lock *lock = __lock;
    thread_lock_release(lock);
}
static void
wait_on_irq_lock_release_callback(void *__lock)
{
    struct irq_lock *lock = __lock;
    irq_lock_release(lock);
}

int
wait_on_spin_unlock(struct waitqueue *queue, spinlock_t *to_unlock)
{
    return wait_on_with_callback(queue,
                                 wait_on_spin_unlock_callback,
                                 to_unlock);
}
int
wait_on_thread_lock_release(struct waitqueue *queue, thread_lock_t *to_unlock)
{
    return wait_on_with_callback(queue,
                                 wait_on_thread_lock_release_callback,
                                 to_unlock);
}
int
wait_on_irq_lock_release(struct waitqueue *queue, irq_lock_t *to_unlock)
{
    return wait_on_with_callback(queue,
                                 wait_on_irq_lock_release_callback,
                                 to_unlock);
}

int
wake_single(struct waitqueue *queue)
{
    irq_lock_acquire(&queue->lock);
    ilist_node_t *node = ilist_pop_head(&queue->waiting_threads);
    if(node != NULL)
    {
        queue->num_threads--;

        struct thread_state *thread =
            container_of(node, struct thread_state, waitqueue_node);
        thread->waitqueue = NULL;
        thread_wake(thread);
    }
    irq_lock_release(&queue->lock);
    return 0;
}

int
wake_all(struct waitqueue *queue)
{
    irq_lock_acquire(&queue->lock);
    ilist_node_t *node;

    do
    {
        node = ilist_pop_head(&queue->waiting_threads);
        if(node == NULL)
        {
            break;
        }
        queue->num_threads--;

        struct thread_state *thread =
            container_of(node, struct thread_state, waitqueue_node);
        thread->waitqueue = NULL;
        thread_wake(thread);
    } while(1);

    irq_lock_release(&queue->lock);
    return 0;
}

int
waitqueue_disable(struct waitqueue *queue)
{
    irq_lock_acquire(&queue->lock);
    queue->flags |= WAITQUEUE_DISABLED;
    irq_lock_release(&queue->lock);
    return 0;
}
