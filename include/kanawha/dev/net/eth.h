#ifndef __KANAWHA__ETH_DEV_H__
#define __KANAWHA__ETH_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/net/ethernet.h>
#include <kanawha/sysfs/vfs.h>

struct eth_dev;
struct eth_driver;

struct eth_frame
{
    struct eth_dev *dev;
    struct eth_raw_frame *data;
};

#define ETH_DEV_READ_MAC_SIG(RET,ARG,...)\
RET(int)\
ARG(struct eth_mac_addr *, addr_out)

#define ETH_DEV_ALLOC_FRAME_SIG(RET,ARG,...)\
RET(struct eth_frame *)\
ARG(size_t, frame_size)\
ARG(unsigned long, flags)

#define ETH_DEV_SEND_FRAME_SIG(RET,ARG,...)\
RET(int)\
ARG(struct eth_frame *, frame)

#define ETH_DEV_DROP_FRAME_SIG(RET,ARG,...)\
RET(int)\
ARG(struct eth_frame *, frame)

#define ETH_DEV_BEGIN_RECV_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)

#define ETH_DEV_END_RECV_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)

#define ETHERNET_DEVICE_OP_LIST(OP, ...)\
OP(read_mac, ETH_DEV_READ_MAC_SIG, ##__VA_ARGS__)\
OP(alloc_frame, ETH_DEV_ALLOC_FRAME_SIG, ##__VA_ARGS__)\
OP(send_frame, ETH_DEV_SEND_FRAME_SIG, ##__VA_ARGS__)\
OP(drop_frame, ETH_DEV_DROP_FRAME_SIG, ##__VA_ARGS__)\
OP(begin_recv, ETH_DEV_BEGIN_RECV_SIG, ##__VA_ARGS__)\
OP(end_recv, ETH_DEV_END_RECV_SIG, ##__VA_ARGS__)\

struct eth_driver {
DECLARE_OP_LIST_PTRS(ETHERNET_DEVICE_OP_LIST, struct eth_dev *);
};

struct eth_dev {
    struct dev dev;
    struct eth_driver *driver;

    irq_lock_t recv_callback_lock;
    ilist_t recv_callback_list;
    unsigned receiving : 1;
};

DEFINE_OP_LIST_WRAPPERS(
        ETHERNET_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        eth_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_DEV_TYPE(eth_dev);

#undef ETH_DEV_READ_MAC_SIG
#undef ETH_DEV_ALLOC_FRAME_SIG
#undef ETH_DEV_SEND_FRAME_SIG
#undef ETH_DEV_RECV_FRAME_SIG
#undef ETH_DEV_BEGIN_RECV_SIG
#undef ETH_DEV_END_RECV_SIG
#undef ETHERNET_DEVICE_OP_LIST

/*
 * External Interface
 */

static inline int
eth_frame_send(
        struct eth_frame *frame)
{
    return eth_dev_send_frame(frame->dev, frame);
}

static inline int
eth_frame_drop(
        struct eth_frame *frame)
{
    return eth_dev_drop_frame(frame->dev, frame);
}

struct eth_dev_recv_hook;

#define ETH_RECV_IGNORE  (0)
#define ETH_RECV_CLAIM   (1)
#define ETH_RECV_DROP    (2)
#define ETH_RECV_FORWARD (3)

struct eth_dev_recv_hook *
hook_eth_dev_receive(
        struct eth_dev *dev,
        int(*on_recv)(
            struct eth_dev *dev,
            void *buffer,
            size_t buflen,
            unsigned long flags,
            void *priv_state),
        void *priv_state
        );

int
unhook_eth_dev_receive(
        struct eth_dev_recv_hook *hook);

/* 
 * Driver Internal Interface
 */

// To be called by drivers when the device receives a packet
int
eth_dev_internal_on_recv(
        struct eth_dev *dev,
        void *buffer,
        size_t buflen,
        unsigned long flags);

#endif
