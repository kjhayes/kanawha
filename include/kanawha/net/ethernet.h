#ifndef __KANAWHA__NET_ETHERNET_H__
#define __KANAWHA__NET_ETHERNET_H__

#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/endian.h>
#include <kanawha/printk.h>

#define ETH_MAC_ADDR_LEN 6
#define ETH_FRAME_HEADER_LEN 14

struct eth_mac_addr {
    uint8_t data[ETH_MAC_ADDR_LEN];
} __attribute__((packed));

ASSERT_TYPE_SIZE(struct eth_mac_addr, ETH_MAC_ADDR_LEN);

struct eth_frame_header{
    struct eth_mac_addr src_addr;
    struct eth_mac_addr dst_addr;
    be16_t type;
} __attribute__((packed));

struct eth_frame {
    struct eth_frame_header hdr;
    uint8_t data[];
};

ASSERT_TYPE_SIZE(struct eth_frame_header, ETH_FRAME_HEADER_LEN);

int
dump_eth_mac_addr(
        printk_f *printer,
        struct eth_mac_addr *addr);

#endif
