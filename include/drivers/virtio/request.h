#ifndef __KANAWHA__VIRTIO_REQUEST_H__
#define __KANAWHA__VIRTIO_REQUEST_H__

#include <drivers/virtio/queue.h>
#include <kanawha/list.h>
#include <kanawha/pointer.h>

typedef void(virtio_request_callback_f)(struct virtio_request *req,
                                        void *priv_state);

struct virtio_request
{
    enum
    {
        VIRTIO_REQUEST_UNLAUNCHED,
        VIRTIO_REQUEST_LAUNCHED,
        VIRTIO_REQUEST_COMPLETED,
    } state;

    uint16_t num_buffers;
    uint16_t root_descriptor;
    uint16_t tail_descriptor;
    uint16_t avail_slot;

    ilist_node_t queue_node;
    struct virtio_queue *queue;

    virtio_request_callback_f *complete_callback;
    void *complete_callback_state;

    size_t len_written;
};

struct virtio_request *
virtio_request_create(struct virtio_queue *queue);
int
virtio_request_destroy(struct virtio_request *request);

// Device Readonly
int
virtio_request_append_input(struct virtio_request *req,
                            void __phys *buffer,
                            size_t active_size);

// Device Writeable
int
virtio_request_append_output(struct virtio_request *req,
                             void __phys *buffer,
                             size_t active_size);

static inline int
virtio_request_launch(struct virtio_request *req)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(req->queue));

    res = virtio_queue_launch_request(req->queue, req);
    if(res)
    {
        return res;
    }

    return 0;
}

static inline int
virtio_request_await(struct virtio_request *req)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(req->queue));

    while(1)
    {
        res = virtio_queue_try_finish_request(req->queue, req);
        if(res)
        {
            virtio_queue_notify(req->queue);
            virtio_queue_handle_used_notification(req->queue);
            continue;
        }
        break;
    }

    return 0;
}

// 0 -> Request Completed
// 1 -> Request Pending
// <0 -> Error
static inline int
virtio_request_try_complete(struct virtio_request *req)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(req->queue));

    res = virtio_queue_try_finish_request(req->queue, req);
    if(res)
    {
        return 1;
    }

    return 0;
}

int
virtio_request_set_completion_callback(struct virtio_request *req,
                                       virtio_request_callback_f *callback,
                                       void *priv_state);

int
virtio_transact(struct virtio_queue *queue,
                size_t input_count,
                void **input_datas,
                size_t *input_sizes,
                size_t output_count,
                void **output_datas,
                size_t *output_sizes);

static inline int
virtio_transact_1_1(struct virtio_queue *queue,
                    void *input_buffer,
                    size_t input_buflen,
                    void *output_buffer,
                    size_t output_buflen)
{
    return virtio_transact(queue,
                           1,
                           &input_buffer,
                           &input_buflen,
                           1,
                           &output_buffer,
                           &output_buflen);
}

#endif
