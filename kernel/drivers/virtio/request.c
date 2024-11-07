
#include <drivers/virtio/request.h>
#include <drivers/virtio/queue.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>


struct virtio_request *
virtio_request_create(
        struct virtio_queue *queue)
{
    struct virtio_request *request = kmalloc(sizeof(struct virtio_request));
    if(request == NULL) {
        return NULL;
    }
    memset(request, 0, sizeof(struct virtio_request));

    request->queue = queue;
    request->num_buffers = 0;

    int irq_flags = spin_lock_irq_save(&queue->req_lock);
    ilist_push_tail(&queue->unlaunched_reqs, &request->queue_node);
    spin_unlock_irq_restore(&queue->req_lock, irq_flags);
    return request;
}

int
virtio_request_destroy(
        struct virtio_request *request)
{
    int res;

    struct virtio_queue *queue = request->queue;

    if(queue != NULL) {

        int irq_flags = spin_lock_irq_save(&queue->req_lock);

        // We can only destroy unlaunched requests
        if(request->state != VIRTIO_REQUEST_UNLAUNCHED) {
            spin_unlock_irq_restore(&queue->req_lock, irq_flags);
            return -EINVAL;
        }

        ilist_remove(&queue->unlaunched_reqs, &request->queue_node);

        spin_unlock_irq_restore(&queue->req_lock, irq_flags);

        if(request->num_buffers > 0) {
            res = virtio_queue_free_desc_chain(
                    queue,
                    request->root_descriptor);
            if(res) {
                eprintk("Failed to free virtio_request descriptor chain!\n");
            }
        }

    } else {
        wprintk("Destroying orphaned virtio_request!\n");
    }

    kfree(request);

    return 0;
}

static int
virtio_request_append(
        struct virtio_request *req,
        void __phys *buffer,
        size_t bufsize,
        int output)
{
    int res;

    struct virtio_queue *queue = req->queue;
    DEBUG_ASSERT(KERNEL_ADDR(queue));

    uint16_t desc;
    if(req->num_buffers == 0) {
        res = virtio_queue_alloc_desc(
                queue,
                &desc);
        if(res) {
            return res;
        }
        req->root_descriptor = desc;
    } else {
        res = virtio_queue_alloc_chained_desc(
                queue,
                req->tail_descriptor,
                &desc);
        if(res) {
            return res;
        }
    }

    req->tail_descriptor = desc;
    
    res = virtio_queue_point_desc(
            queue,
            desc,
            buffer,
            bufsize,
            output);
    if(res) {
        eprintk("virtio_queue: Failed to point allocated descriptor! (leaking descriptor memory) (err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

int
virtio_request_append_input(
        struct virtio_request *req,
        void __phys *buffer,
        size_t bufsize)
{
    return virtio_request_append(
            req,
            buffer,
            bufsize,
            0);
}

int
virtio_request_append_output(
        struct virtio_request *req,
        void __phys *buffer,
        size_t bufsize)
{
    return virtio_request_append(
            req,
            buffer,
            bufsize,
            1);
}

