#ifndef __KANAWHA__VIRTIO_REQUEST_H__
#define __KANAWHA__VIRTIO_REQUEST_H__

#include <kanawha/list.h>
#include <kanawha/waitqueue.h>

struct virtio_buffer
{
    ilist_node_t list_node;

    paddr_t phys_addr;
    void *virt_addr;
    size_t size;

    int is_response : 1;
};

struct virtio_request
{
    ilist_t buffers;

    struct virtio_queue *queue;
};

struct virtio_request *
virtio_request_create(
        struct virtio_queue *queue);
int
virtio_request_destroy(
        struct virtio_request *req);

// Allocate, populate and append
// a buffer with the provided data
int
virtio_request_append_req_data(
        struct virtio_request *req,
        void *data,
        size_t data_len);

// Allocate and append a response buffer which
// is device writable
void *
virtio_request_append_resp_buf(
        struct virtio_request *req,
        size_t buf_len);

// Move this request into the available ring
int
virtio_request_launch(
        struct virtio_request *req);

// Wait for the device to move this request into the used ring
int
virtio_request_await(
        struct virtio_request *req);

#endif
