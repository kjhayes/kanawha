#ifndef __KANAWHA__ETH_DEV_H__
#define __KANAWHA__ETH_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/net/ethernet.h>
#include <kanawha/fs/sys/vfs.h>

struct eth_dev;
struct eth_driver;

#define ETH_DEV_READ_MAC_SIG(RET,ARG)\
RET(int)\
ARG(struct eth_mac_addr *, addr_out)

#define ETH_DEV_SEND_FRAME_SIG(RET,ARG)\
RET(int)\
ARG(struct eth_frame *, frame)\
ARG(size_t, len)\
ARG(unsigned long, flags)\

#define ETHERNET_DEVICE_OP_LIST(OP, ...)\
OP(read_mac, ETH_DEV_READ_MAC_SIG, ##__VA_ARGS__)\
OP(send_frame, ETH_DEV_SEND_FRAME_SIG, ##__VA_ARGS__)

DECLARE_DEV_TYPE(eth, ETHERNET_DEVICE_OP_LIST);

#undef ETH_DEV_READ_MAC_SIG
#undef ETH_DEV_SEND_FRAME_SIG
#undef ETHERNET_DEVICE_OP_LIST

#endif
