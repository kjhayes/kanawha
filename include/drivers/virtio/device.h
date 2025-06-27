#ifndef __KANAWHA__VIRTIO_DEVICE_H__
#define __KANAWHA__VIRTIO_DEVICE_H__

#include <kanawha/ops.h>
#include <kanawha/types.h>
#include <kanawha/list.h>

#define VIRTIO_DEVICE_READ_STATUS_SIG(RET,ARG)\
RET(uint8_t)

#define VIRTIO_DEVICE_SET_STATUS_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, mask_to_set)

#define VIRTIO_DEVICE_RESET_SIG(RET,ARG)\
RET(int)

#define VIRTIO_DEVICE_CFG_WRITEB(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint8_t, value)
#define VIRTIO_DEVICE_CFG_WRITEW(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint16_t, value)
#define VIRTIO_DEVICE_CFG_WRITEL(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint32_t, value)
#define VIRTIO_DEVICE_CFG_WRITEQ(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint64_t, value)

#define VIRTIO_DEVICE_CFG_READB(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint8_t *, out)
#define VIRTIO_DEVICE_CFG_READW(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint16_t *, out)
#define VIRTIO_DEVICE_CFG_READL(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint32_t *, out)
#define VIRTIO_DEVICE_CFG_READQ(RET,ARG)\
RET(int)\
ARG(size_t, offset)\
ARG(uint64_t *, out)

// 1 -> Supports Feature, 0 -> Does Not Support Feature, <0 -> ERROR
#define VIRTIO_DEVICE_CHECK_FEATURE_SIG(RET,ARG)\
RET(int)\
ARG(size_t, feat_bit)

#define VIRTIO_DEVICE_ACCEPT_FEATURE_SIG(RET,ARG)\
RET(int)\
ARG(size_t, feat_bit)

#define VIRTIO_DEVICE_NOTIFY_SIG(RET,ARG)\
RET(int)\
ARG(size_t, queue)

#define VIRTIO_DEVICE_INIT_QUEUES_SIG(RET,ARG)\
RET(int)
#define VIRTIO_DEVICE_DEINIT_QUEUES_SIG(RET,ARG)\
RET(int)

#define VIRTIO_DEVICE_OP_LIST(OP, ...)\
OP(read_status, VIRTIO_DEVICE_READ_STATUS_SIG, ##__VA_ARGS__)\
OP(set_status, VIRTIO_DEVICE_SET_STATUS_SIG, ##__VA_ARGS__)\
OP(reset, VIRTIO_DEVICE_RESET_SIG, ##__VA_ARGS__)\
OP(check_feature, VIRTIO_DEVICE_CHECK_FEATURE_SIG, ##__VA_ARGS__)\
OP(accept_feature, VIRTIO_DEVICE_ACCEPT_FEATURE_SIG, ##__VA_ARGS__)\
OP(cfg_writeb, VIRTIO_DEVICE_CFG_WRITEB, ##__VA_ARGS__)\
OP(cfg_writew, VIRTIO_DEVICE_CFG_WRITEW, ##__VA_ARGS__)\
OP(cfg_writel, VIRTIO_DEVICE_CFG_WRITEL, ##__VA_ARGS__)\
OP(cfg_writeq, VIRTIO_DEVICE_CFG_WRITEQ, ##__VA_ARGS__)\
OP(cfg_readb, VIRTIO_DEVICE_CFG_READB, ##__VA_ARGS__)\
OP(cfg_readw, VIRTIO_DEVICE_CFG_READW, ##__VA_ARGS__)\
OP(cfg_readl, VIRTIO_DEVICE_CFG_READL, ##__VA_ARGS__)\
OP(cfg_readq, VIRTIO_DEVICE_CFG_READQ, ##__VA_ARGS__)\
OP(notify, VIRTIO_DEVICE_NOTIFY_SIG, ##__VA_ARGS__)\
OP(init_queues, VIRTIO_DEVICE_INIT_QUEUES_SIG, ##__VA_ARGS__)\
OP(deinit_queues, VIRTIO_DEVICE_DEINIT_QUEUES_SIG, ##__VA_ARGS__)\

struct virtio_device;
struct virtio_driver;

struct virtio_device_ops {
DECLARE_OP_LIST_PTRS(VIRTIO_DEVICE_OP_LIST, struct virtio_device *)
};

struct virtio_device
{
    ilist_node_t global_node;

    struct virtio_device_ops *ops;

    struct virtio_driver *driver;
    ilist_node_t driver_node;

    size_t num_queues;
    struct virtio_queue ** queues;

    uint16_t virtio_id;
    unsigned is_legacy : 1;

    void *driver_priv;
};

DEFINE_OP_LIST_WRAPPERS(
        VIRTIO_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        virtio_device,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

#undef VIRTIO_DEVICE_READ_STATUS_SIG
#undef VIRTIO_DEVICE_SET_STATUS_SIG
#undef VIRTIO_DEVICE_RESET_SIG
#undef VIRITO_DEVICE_OP_LIST

int
register_virtio_device(
        struct virtio_device *device);

#endif
