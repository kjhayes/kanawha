#ifndef __KANAWHA__WAITQUEUE_H__
#define __KANAWHA__WAITQUEUE_H__

#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>

#define WAITQUEUE_DISABLED (1ULL << 0)

struct waitqueue
{
    irq_lock_t lock;
    unsigned long flags;
    ilist_t waiting_threads;
    size_t num_threads;

    unsigned dyn_name : 1;
    char *name;
};

typedef void(wait_on_callback_f)(void *);

int
waitqueue_init(struct waitqueue *queue);

int
waitqueue_name(struct waitqueue *queue, const char *to_copy);

// Disables the waitqueue, wakes all threads,
// and waits for all threads to have deattached
// themselves from the queue.
int
waitqueue_deinit(struct waitqueue *queue);

// Have the current thread go to sleep
// waiting on the queue.
// (Calls "callback" right before switching threads)
int
wait_on_with_callback(struct waitqueue *queue,
                      wait_on_callback_f *callback,
                      void *priv_state);

// Callback-less version
int
wait_on(struct waitqueue *queue);

// After placing ourselves on
// the queue, unlock a lock.
int
wait_on_spin_unlock(struct waitqueue *queue, spinlock_t *to_unlock);
int
wait_on_thread_lock_release(struct waitqueue *queue, thread_lock_t *to_unlock);
int
wait_on_irq_lock_release(struct waitqueue *queue, irq_lock_t *to_unlock, int *irq_flags);

// Wake a single thread waiting on this queue
int
wake_single(struct waitqueue *queue);

// Wake every thread waiting on this queue
int
wake_all(struct waitqueue *queue);

// Make it so any thread
// which tries to sleep on this
// queue will immediately wake,
//
// NOTE: This does not wake existing threads waiting
//       on the queue, if that is needed, call
//         wake_all
//       after waitqueue_disable
//
// Useful for a when the queue corresponds to a
// "dead" object (ex. a zombie thread)
int
waitqueue_disable(struct waitqueue *queue);

#endif
