
#include <drivers/virtio/request.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

static struct virtio_buffer *
virtio_buffer_create(
        size_t bufsize)
{
    return NULL;
}

static int
virtio_buffer_destroy(
        struct virtio_buffer *buf)
{
    return -EUNIMPL;
}

struct virtio_request *
virtio_request_create(
        struct virtio_queue *queue)
{
    struct virtio_request *req = kmalloc(sizeof(struct virtio_request));
    if(req == NULL) {
        return req;
    }
    memset(req, 0, sizeof(struct virtio_request));

    ilist_init(&req->buffers);
    req->queue = queue;

    return req;
}

int
virtio_request_destroy(
        struct virtio_request *req)
{

}

int
virtio_request_append_req_data(
        struct virtio_request *req,
        void *data,
        size_t data_len)
{

}

void *
virtio_request_append_resp_buf(
        struct virtio_request *req,
        size_t buf_len)
{

}

int
virtio_request_launch(
        struct virtio_request *req)
{

}

int
virtio_request_await(
        struct virtio_request *req)
{

}

