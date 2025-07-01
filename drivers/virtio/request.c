
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

    request->complete_callback = NULL;
    request->complete_callback_state = NULL;

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

    req->num_buffers++;

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

int
virtio_request_set_completion_callback(
        struct virtio_request *req,
        virtio_request_callback_f *callback,
        void *state)
{
    if(req->complete_callback != NULL) {
        req->complete_callback_state = state;
        req->complete_callback = callback;
        return 0;
    }
    return -EALREADY;
}

int
virtio_request_clear_complete_callback(
        struct virtio_request *req)
{
    req->complete_callback = NULL;
    req->complete_callback_state = NULL;
    return 0;
}

int
virtio_transact(
        struct virtio_queue *queue,
        size_t input_count,
        void **input_datas,
        size_t *input_sizes,
        size_t output_count,
        void **output_datas,
        size_t *output_sizes)
{
    int res;

    size_t allocated_inputs = 0;
    size_t allocated_outputs = 0;
    dma_addr_t input_buffers[input_count];
    dma_addr_t output_buffers[output_count];
    struct virtio_request *req = NULL;

    req = virtio_request_create(queue);
    if(req == NULL) {
        res = -ENOMEM;
        goto exit;
    }

    for(size_t i = 0; i < input_count; i++) {
        res = dma_alloc(
                input_sizes[i],
                0,
                0,
                &input_buffers[i]);
        if(res) {
            goto exit;
        }
        allocated_inputs++;

        void *data = dma_virt_addr(input_buffers[i]);
        memcpy(data, input_datas[i], input_sizes[i]);

        res = virtio_request_append_input(
                req,
                dma_phys_addr(input_buffers[i]),
                input_sizes[i]);
        if(res) {
            goto exit;
        }
    }
    for(size_t i = 0; i < output_count; i++) {
        res = dma_alloc(
                output_sizes[i],
                0,
                0,
                &output_buffers[i]);
        if(res) {
            goto exit;
        }
        allocated_outputs++;

        res = virtio_request_append_output(
                req,
                dma_phys_addr(output_buffers[i]),
                output_sizes[i]);
        if(res) {
            goto exit;
        }
    }

    res = virtio_request_launch(req);
    if(res) {
        goto exit;
    }

    res = virtio_request_await(req);
    if(res) {
        goto exit;
    }

    for(size_t i = 0; i < output_count; i++) {
        memcpy(
            output_datas[i],
            dma_virt_addr(output_buffers[i]),
            output_sizes[i]); 
    }

    res = 0;

exit:
    if(req) {
        virtio_request_destroy(req);
    }

    for(size_t i = 0; i < allocated_inputs; i++) {
        dma_free(input_buffers[i], input_sizes[i]);
    }
    for(size_t i = 0; i < allocated_outputs; i++) {
        dma_free(output_buffers[i], output_sizes[i]);
    }

    return res;
}

