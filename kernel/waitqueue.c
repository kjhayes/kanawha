
#include <kanawha/waitqueue.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/scheduler.h>
#include <kanawha/thread.h>
#include <kanawha/errno.h>

int
wait_on(struct waitqueue *queue)
{
    int res;

    struct thread_state *cur = current_thread();

    struct thread_state *next = force_resched();
    if(next == NULL) {
        eprintk("wait_on: force_resched() returned NULL!\n");
        return -EINVAL;
    }

    int irq_flags = spin_lock_irq_save(&queue->lock);

    // (Instead of going from RUNNING -> READY we will
    //  go from TIRED -> SLEEPING on next thread_switch)
    res = thread_tire(cur);
    if(res) {
        spin_unlock_irq_restore(&queue->lock, irq_flags);
        return res;
    }

    // Place our thread onto the waitqueue
    ilist_push_tail(&queue->waiting_threads, &cur->waitqueue_node);
    queue->num_threads++;

    // Unlock the queue
    spin_unlock(&queue->lock);

    // Force a reschedule (TIRED -> SLEEPING)
    thread_switch(force_resched());

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

