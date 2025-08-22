#ifndef __KANAWHA__IPV4_DEV_H__
#define __KANAWHA__IPV4_DEV_H__

#include <kanawha/registry.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/net/ip.h>

struct ipv4_dev;
struct ipv4_driver;

struct ipv4_packet
{
    struct ipv4_dev *dev;
    struct ipv4_raw_packet *data;
};

#define IPV4_DEV_ALLOC_PACKET_SIG(RET,ARG,...)\
RET(struct ipv4_packet *)\
ARG(size_t, packet_size)\
ARG(unsigned long, flags)

#define IPV4_DEV_SEND_PACKET_SIG(RET,ARG,...)\
RET(int)\
ARG(struct ipv4_packet *, pkt)

#define IPV4_DEV_DROP_PACKET_SIG(RET,ARG,...)\
RET(int)\
ARG(struct ipv4_packet *, pkt)

#define IPV4_DEV_BEGIN_RECV_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)

#define IPV4_DEV_END_RECV_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)

#define IPV4_DEVICE_OP_LIST(OP, ...)\
OP(alloc_packet, IPV4_DEV_ALLOC_PACKET_SIG, ##__VA_ARGS__)\
OP(send_packet, IPV4_DEV_SEND_PACKET_SIG, ##__VA_ARGS__)\
OP(drop_packet, IPV4_DEV_DROP_PACKET_SIG, ##__VA_ARGS__)\
OP(begin_recv, IPV4_DEV_BEGIN_RECV_SIG, ##__VA_ARGS__)\
OP(end_recv, IPV4_DEV_END_RECV_SIG, ##__VA_ARGS__)\

struct ipv4_driver {
DECLARE_OP_LIST_PTRS(IPV4_DEVICE_OP_LIST, struct ipv4_dev *);
};

struct ipv4_dev {
    struct registry_node registry_node;
    struct ipv4_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        IPV4_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        ipv4_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_REGISTRY(ipv4_dev);

#undef IPV4_DEV_READ_MAC_SIG
#undef IPV4_DEV_ALLOC_FRAME_SIG
#undef IPV4_DEV_SEND_FRAME_SIG
#undef IPV4_DEV_RECV_FRAME_SIG
#undef IPV4_DEV_BEGIN_RECV_SIG
#undef IPV4_DEV_END_RECV_SIG
#undef IPV4_DEVICE_OP_LIST

/*
 * External Interface
 */

static inline int
ipv4_packet_send(
        struct ipv4_packet *pkt)
{
    return ipv4_dev_send_packet(pkt->dev, pkt);
}

static inline int
ipv4_packet_drop(
        struct ipv4_packet *pkt)
{
    return ipv4_dev_drop_packet(pkt->dev, pkt);
}

/* 
 * Driver Internal Interface
 */

// To be called by drivers when the device receives a packet

int
ipv4_dev_internal_on_recv(
        struct ipv4_dev *dev,
        void *buffer,
        size_t buflen,
        unsigned long flags);

#endif
