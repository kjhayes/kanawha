#ifndef __KANAWHA__WAITQUEUE_H__
#define __KANAWHA__WAITQUEUE_H__

#include <kanawha/stdint.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/thread.h>

#define WAITQUEUE_DISABLED (1ULL<<0)

struct waitqueue
{
    spinlock_t lock;
    unsigned long flags;
    ilist_t waiting_threads;
    size_t num_threads;
};

int
waitqueue_init(
        struct waitqueue *queue);

int
waitqueue_deinit(
        struct waitqueue *queue);

// Have the current thread go to sleep
// waiting on the queue.
int
wait_on(struct waitqueue *queue);

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
waitqueue_disable(
        struct waitqueue *queue);

#endif
