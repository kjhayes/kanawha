#ifndef __KANAWHA__WAITQUEUE_H__
#define __KANAWHA__WAITQUEUE_H__

#include <kanawha/stdint.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/thread.h>

struct waitqueue
{
    spinlock_t lock;
    ilist_t waiting_threads;
    size_t num_threads;
};

int
wait_on(struct waitqueue *queue);

int
wake_single(struct waitqueue *queue);

int
wake_all(struct waitqueue *queue);

#endif
