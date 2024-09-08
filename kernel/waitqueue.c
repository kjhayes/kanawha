
#include <kanawha/waitqueue.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/scheduler.h>
#include <kanawha/thread.h>
#include <kanawha/assert.h>
#include <kanawha/errno.h>

int
waitqueue_init(
        struct waitqueue *queue)
{
    spinlock_init(&queue->lock);
    queue->flags = 0;
    queue->num_threads = 0;
    ilist_init(&queue->waiting_threads);
    return 0;
}

int
waitqueue_deinit(
        struct waitqueue *queue)
{
    spin_lock(&queue->lock);
    return 0;
}



int
wait_on(struct waitqueue *queue)
{
    int res;

    struct thread_state *cur = current_thread();

    struct thread_state *next = force_resched();
    if(next == NULL) {
        next = idle_thread();
        res = thread_schedule(next);
        if(res) {
            panic("Failed to schedule idle thread on CPU %ld! (err=%s)\n",
                current_cpu_id(),
                errnostr(res));
        }
    }

    DEBUG_ASSERT(KERNEL_ADDR(next));

    int irq_flags = spin_lock_irq_save(&queue->lock);

    if(queue->flags & WAITQUEUE_DISABLED) {
        spin_unlock(&queue->lock);
        thread_switch(next);
        enable_restore_irqs(irq_flags);
    }

    // (Instead of going from RUNNING -> READY we will
    //  go from TIRED -> SLEEPING on next thread_switch)
    res = thread_tire(cur);
    if(res) {
        spin_unlock(&queue->lock);
        thread_switch(next);
        enable_restore_irqs(irq_flags);
        return res;
    }

    // Place our thread onto the waitqueue
    ilist_push_tail(&queue->waiting_threads, &cur->waitqueue_node);
    queue->num_threads++;

    // Unlock the queue
    spin_unlock(&queue->lock);

    // Force a reschedule (TIRED -> SLEEPING)
    thread_switch(next);

    // We're back! (a "wake_*" function should have
    // removed us from the queue already)

    enable_restore_irqs(irq_flags);

    return 0;
}

int
wake_single(struct waitqueue *queue)
{
    int irq_flags = spin_lock_irq_save(&queue->lock);
    ilist_node_t *node = ilist_pop_head(&queue->waiting_threads);
    if(node != NULL) {
        struct thread_state *thread =
            container_of(node, struct thread_state, waitqueue_node);
        thread_wake(thread);
    }
    spin_unlock_irq_restore(&queue->lock, irq_flags);
    return 0;
}

int
wake_all(struct waitqueue *queue)
{
    int irq_flags = spin_lock_irq_save(&queue->lock);
    ilist_node_t *node;

    do {
        node = ilist_pop_head(&queue->waiting_threads);
        if(node == NULL) {
            break;
        }

        struct thread_state *thread =
            container_of(node, struct thread_state, waitqueue_node);
        thread_wake(thread);

    } while(1);

    spin_unlock_irq_restore(&queue->lock, irq_flags);
    return 0;
}

int
waitqueue_disable(
        struct waitqueue *queue)
{
    spin_lock(&queue->lock);
    queue->flags |= WAITQUEUE_DISABLED;
    spin_unlock(&queue->lock);
    return 0;
}

