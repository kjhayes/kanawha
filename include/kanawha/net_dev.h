#ifndef __KANAWHA__NET_DEV_H__
#define __KANAWHA__NET_DEV_H__

#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/net/ethernet.h>

struct net_dev;
struct net_driver;

#define NET_DEV_ETH_SEND_SIG(RET,ARG)\
RET(int)\
ARG(void *, pkt)\
ARG(size_t, pktlen)

#define NET_DEV_ETH_READ_MAC(RET,ARG)\
RET(int)\
ARG(struct eth_mac_addr *, addr_out)

#define NETWORK_DEVICE_OP_LIST(OP, ...)\
OP(eth_send, NET_DEV_ETH_SEND_SIG, ##__VA_ARGS__)\
OP(eth_read_mac, NET_DEV_ETH_READ_MAC, ##__VA_ARGS__)

struct net_driver {
DECLARE_OP_LIST_PTRS(NETWORK_DEVICE_OP_LIST, struct net_dev *)
};

struct net_dev
{
    struct net_driver *driver;

    struct stree_node net_dev_node;
};

DEFINE_OP_LIST_WRAPPERS(
        NETWORK_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        net_dev,
        ->driver->,
        SELF_ACCESSOR)

int
register_net_dev(
        struct net_dev *dev,
        const char *name,
        struct net_driver *driver);

struct net_dev *
net_dev_find(const char *name);

#endif
