#ifndef __KANAWHA__QUEUE_H__
#define __KANAWHA__QUEUE_H__

// A Simple Ring Buffer Implementation

#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/types.h>

struct pqueue
{
    size_t size;
    size_t head;
    size_t tail;
    void **ring;

    irq_lock_t head_lock;
    irq_lock_t tail_lock;
};

static inline int
pqueue_init(struct pqueue *queue, size_t size)
{
    queue->size = size;
    queue->head = 0;
    queue->tail = 0;
    queue->ring = kmalloc(sizeof(struct v_eth_frame *) * size);
    if(queue->ring == NULL)
    {
        return -ENOMEM;
    }
    irq_lock_init(&queue->head_lock);
    irq_lock_init(&queue->tail_lock);
    return 0;
}

static inline int
pqueue_deinit(struct pqueue *queue)
{
    irq_lock_acquire(&queue->head_lock);
    irq_lock_acquire(&queue->tail_lock);
    kfree(queue->ring);
    queue->size = 0;
    queue->head = 0;
    queue->tail = 0;
    return 0;
}

static inline int
pqueue_empty(struct pqueue *queue)
{
    return queue->head == queue->tail;
}

static inline int
pqueue_full(struct pqueue *queue)
{
    return ((queue->head + 1) % queue->size) == queue->tail;
}

static inline int
pqueue_try_push(struct pqueue *queue, void *elem)
{
    irq_lock_acquire(&queue->head_lock);
    if(pqueue_full(queue))
    {
        irq_lock_release(&queue->head_lock);
        return -ENOMEM;
    }
    queue->ring[queue->head] = elem;
    queue->head = (queue->head + 1) % queue->size;
    irq_lock_release(&queue->head_lock);
    return 0;
}

static inline int
pqueue_try_pull(struct pqueue *queue, void **elem_out)
{
    irq_lock_acquire(&queue->tail_lock);
    if(pqueue_empty(queue))
    {
        irq_lock_release(&queue->tail_lock);
        return -ENXIO;
    }
    if(elem_out)
    {
        *elem_out = queue->ring[queue->tail];
    }
    queue->tail = (queue->tail + 1) % queue->size;
    irq_lock_release(&queue->tail_lock);
    return 0;
}

#endif
