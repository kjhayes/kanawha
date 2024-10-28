#ifndef __KANAWHA__VIRTIO_TRANSPORT_H__
#define __KANAWHA__VIRTIO_TRANSPORT_H__

#include <kanawha/ops.h>

#define VIRTIO_XPORT_READ_STATUS_SIG(RET,ARG)\
RET(uint64_t)

#define VIRTIO_XPORT_SET_STATUS_SIG(RET,ARG)\
RET(int)\
ARG(uint64_t, mask_to_set)

#define VIRTIO_XPORT_RESET_SIG(RET,ARG)\
RET(int)

#define VIRTIO_XPORT_OP_LIST(OP, ...)\
OP(read_status, VIRTIO_XPORT_READ_STATUS_SIG, ##__VA_ARGS__)\
OP(set_status, VIRTIO_XPORT_SET_STATUS_SIG, ##__VA_ARGS__)\
OP(reset, VIRTIO_XPORT_RESET_SIG, ##__VA_ARGS__)

struct virtio_device;

struct virtio_transport {
DECLARE_OP_LIST_PTRS(VIRTIO_XPORT_OP_LIST, struct virtio_device *)
};

struct virtio_device
{
    ilist_node_t global_node;

    struct virtio_transport *transport;

    struct virtio_driver *driver;
    ilist_node_t driver_node;

    uint16_t virtio_id;
};

DEFINE_OP_LIST_WRAPPERS(
        VIRTIO_XPORT_OP_LIST,
        static inline,
        /* No Prefix */,
        virtio_device,
        ->transport->,
        SELF_ACCESSOR);

#undef VIRTIO_XPORT_READ_STATUS_SIG
#undef VIRTIO_XPORT_SET_STATUS_SIG
#undef VIRTIO_XPORT_RESET_SIG
#undef VIRITO_XPORT_OP_LIST

int
register_virtio_device(
        struct virtio_device *device);

#endif
