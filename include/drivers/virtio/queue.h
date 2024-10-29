#ifndef __KANAWHA__VIRTIO_VIRT_QUEUE_H__
#define __KANAWHA__VIRTIO_VIRT_QUEUE_H__

#include <kanawha/ops.h>
#include <kanawha/endian.h>

struct virtio_queue_desc
{
    le64_t addr; // Data Physical Address
    le32_t len; // Data Length

#define VIRTQ_DESC_F_NEXT 1 // continues via the next field
#define VIRTQ_DESC_F_WRITE 2 // device write-only (otherwise device read-only)
#define VIRTQ_DESC_F_INDIRECT 4 // the buffer contains a list of buffer descriptors
    le16_t flags;

    /* Next field if flags & NEXT */
    le16_t next;
};

#define VIRTIO_QUEUE_NOTIFY_SIG(RET,ARG)\
RET(int)

#define VIRTIO_QUEUE_OP_LIST(OP, ...)\
OP(notify, VIRTIO_QUEUE_NOTIFY_SIG, ##__VA_ARGS__)\

struct virtio_queue;

struct virtio_queue_ops {
DECLARE_OP_LIST_PTRS(VIRTIO_QUEUE_OP_LIST, struct virtio_queue *);
};

struct virtio_queue
{
    struct virtio_queue_ops *ops;

    struct virtio_device *device;

    uint16_t index;
    uint16_t queue_size;
};

static inline uint16_t
virtio_queue_index(
        struct virtio_device *dev,
        struct virtio_queue *queue)
{
    return queue->index;
}

DEFINE_OP_LIST_WRAPPERS(
        VIRTIO_QUEUE_OP_LIST,
        static inline,
        /* No Prefix */,
        virtio_queue,
        ->ops->,
        SELF_ACCESSOR);

#undef VIRTIO_QUEUE_NOTIFY_SIG
#undef VIRTIO_QUEUE_OP_LIST

#endif
