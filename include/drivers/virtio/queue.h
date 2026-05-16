#ifndef __KANAWHA__VIRTIO_VIRT_QUEUE_H__
#define __KANAWHA__VIRTIO_VIRT_QUEUE_H__

#include <kanawha/dma.h>
#include <kanawha/endian.h>
#include <kanawha/ops.h>

struct virtio_queue_desc
{
    le64_t addr; // Data Physical Address
    le32_t len;  // Data Length

#define VIRTQ_DESC_F_NEXT 1  // continues via the next field
#define VIRTQ_DESC_F_WRITE 2 // device write-only (otherwise device read-only)
#define VIRTQ_DESC_F_INDIRECT                                                  \
    4 // the buffer contains a list of buffer descriptors
    le16_t flags;

    /* Next field if flags & NEXT */
    le16_t next;
};

_Static_assert(sizeof(struct virtio_queue_desc) == 16,
               "virtio_queue_desc is not 16 bytes wide!");

struct virtio_queue_avail
{
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
    le16_t flags;
    le16_t idx;
    le16_t ring[];
};
_Static_assert(sizeof(struct virtio_queue_avail) == 4,
               "virito_queue_avail is not 4 bytes wide!");

struct virtio_queue_used_elem
{
    le32_t id;
    le32_t len;
};

struct virtio_queue_used
{
#define VIRTQ_USED_F_NO_NOTIFY 1
    le16_t flags;
    le16_t idx;
    struct virtio_queue_used_elem ring[];
};

#define VIRTIO_QUEUE_NOTIFY_SIG(RET, ARG, ...) RET(int)

#define VIRTIO_QUEUE_SET_DESC_TABLE_SIG(RET, ARG, ...)                         \
    RET(int)                                                                   \
    ARG(void __phys *, desc_table_ptr)

#define VIRTIO_QUEUE_SET_AVAIL_RING_SIG(RET, ARG, ...)                         \
    RET(int)                                                                   \
    ARG(void __phys *, avail_ring_ptr)

#define VIRTIO_QUEUE_SET_USED_RING_SIG(RET, ARG, ...)                          \
    RET(int)                                                                   \
    ARG(void __phys *, used_ring_ptr)

#define VIRTIO_QUEUE_ENABLE_SIG(RET, ARG, ...) RET(int)

#define VIRTIO_QUEUE_DISABLE_SIG(RET, ARG, ...) RET(int)

#define VIRTIO_QUEUE_OP_LIST(OP, ...)                                          \
    OP(notify, VIRTIO_QUEUE_NOTIFY_SIG, ##__VA_ARGS__)                         \
    OP(set_desc_table, VIRTIO_QUEUE_SET_DESC_TABLE_SIG, ##__VA_ARGS__)         \
    OP(set_avail_ring, VIRTIO_QUEUE_SET_AVAIL_RING_SIG, ##__VA_ARGS__)         \
    OP(set_used_ring, VIRTIO_QUEUE_SET_USED_RING_SIG, ##__VA_ARGS__)           \
    OP(enable, VIRTIO_QUEUE_ENABLE_SIG, ##__VA_ARGS__)                         \
    OP(disable, VIRTIO_QUEUE_DISABLE_SIG, ##__VA_ARGS__)

struct virtio_queue;
struct virtio_request;

struct virtio_queue_ops
{
    DECLARE_OP_LIST_PTRS(VIRTIO_QUEUE_OP_LIST, struct virtio_queue *);
};

struct virtio_queue
{
    struct virtio_queue_ops *ops;

    struct virtio_device *device;

    uint16_t index;
    uint16_t queue_size;

    dma_addr_t dma_region;
    size_t dma_size;

    spinlock_t desc_lock;
    struct virtio_queue_desc *desc_table;
    unsigned long *desc_bitmap;

    spinlock_t avail_lock;
    struct virtio_queue_avail *avail_ring;
    unsigned long *avail_bitmap;

    spinlock_t used_lock;
    size_t last_used_idx;
    struct virtio_queue_used *used_ring;

    spinlock_t req_lock;
    ilist_t unlaunched_reqs;
    ilist_t launched_reqs;
};

int
virtio_queue_init_struct(struct virtio_queue *queue,
                         struct virtio_queue_ops *ops,
                         struct virtio_device *device,
                         uint16_t index,
                         uint16_t queue_size);

int
virtio_queue_deinit_struct(struct virtio_queue *queue);

static inline uint16_t
virtio_queue_index(struct virtio_device *dev, struct virtio_queue *queue)
{
    return queue->index;
}

int
virtio_queue_free_desc_chain(struct virtio_queue *queue, uint16_t root_desc);

int
virtio_queue_alloc_desc(struct virtio_queue *queue, uint16_t *desc);

int
virtio_queue_alloc_chained_desc(struct virtio_queue *queue,
                                uint16_t prev,
                                uint16_t *desc);

int
virtio_queue_point_desc(struct virtio_queue *queue,
                        uint16_t desc,
                        void __phys *buffer,
                        uint32_t size,
                        int output);

// REQUEST_UNLAUNCHED -> REQUEST_LAUNCHED
int
virtio_queue_launch_request(struct virtio_queue *queue,
                            struct virtio_request *req);

// Transition from REQUEST_COMPLETE -> REQUEST_UNLAUNCHED if possible
int
virtio_queue_try_finish_request(struct virtio_queue *queue,
                                struct virtio_request *req);

// To be called by polling routines or IRQ
// handlers
int
virtio_queue_handle_used_notification(struct virtio_queue *queue);

DEFINE_OP_LIST_WRAPPERS(VIRTIO_QUEUE_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        virtio_queue,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR);

#undef VIRTIO_QUEUE_NOTIFY_SIG
#undef VIRTIO_QUEUE_OP_LIST

#endif
