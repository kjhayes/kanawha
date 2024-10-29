#ifndef __KANAWHA__VIRTIO_DRIVER_H__
#define __KANAWHA__VIRTIO_DRIVER_H__

#include <kanawha/ops.h>
#include <kanawha/list.h>

struct virtio_device;

#define VIRTIO_DRIVER_PROBE_SIG(RET,ARG)\
RET(int)\
ARG(struct virtio_device *, dev)

#define VIRTIO_DRIVER_NEGOTIATE_SIG(RET,ARG)\
RET(int)\
ARG(struct virtio_device *, dev)

#define VIRTIO_DRIVER_INIT_SIG(RET,ARG)\
RET(int)\
ARG(struct virtio_device *, dev)

#define VIRTIO_DRIVER_DEINIT_SIG(RET,ARG)\
RET(int)\
ARG(struct virtio_device *, dev)

#define VIRTIO_DRIVER_OP_LIST(OP, ...)\
OP(probe, VIRTIO_DRIVER_PROBE_SIG, ##__VA_ARGS__)\
OP(negotiate, VIRTIO_DRIVER_NEGOTIATE_SIG, ##__VA_ARGS__)\
OP(init_device, VIRTIO_DRIVER_INIT_SIG, ##__VA_ARGS__)\
OP(deinit_device, VIRTIO_DRIVER_DEINIT_SIG, ##__VA_ARGS__)\

struct virtio_driver;

struct virtio_driver_ops {
DECLARE_OP_LIST_PTRS(VIRTIO_DRIVER_OP_LIST, struct virtio_driver *);
};

struct virtio_driver
{
    struct virtio_driver_ops *ops;

    ilist_t device_list;

    ilist_node_t global_node;

    size_t num_ids;
    uint16_t *ids;
};

DEFINE_OP_LIST_WRAPPERS(
        VIRTIO_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        virtio_driver,
        ->ops->,
        SELF_ACCESSOR);

#undef VIRTIO_DRIVER_PROBE_SIG
#undef VIRTIO_DRIVER_NEGOTIATE_SIG
#undef VIRTIO_DRIVER_INIT_SIG
#undef VIRTIO_DRIVER_INIT_DEVICE_SIG
#undef VIRTIO_DRIVER_DEINIT_DEVICE_SIG
#undef VIRTIO_DRIVER_OP_LIST

int
register_virtio_driver(
        struct virtio_driver *driver);

#endif
