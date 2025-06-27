#ifndef __KANAWHA_NET__IP_H__
#define __KANAWHA_NET__IP_H__

#include <kanawha/types.h>
#include <kanawha/endian.h>
#include <kanawha/printk.h>

struct ipv4_addr {
    uint8_t data[4];
} __attribute__((packed));

struct ipv6_addr {
    be16_t data[8];
} __attribute__((packed));

struct ipv4_packet_hdr {
    uint8_t version;
    uint8_t ihl;
    be16_t tos;
    be16_t total_length;
    be16_t flags_and_frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    be16_t checksum;
    struct ipv4_addr src_addr;
    struct ipv4_addr dst_addr;
} __attribute__((packed));

struct ipv4_packet {
    struct ipv4_packet_hdr hdr;
} __attribute__((packed));

int
dump_ipv4_addr(
        printk_f *printer,
        struct ipv4_addr *addr
        );

int
dump_ipv6_addr(
        printk_f *printer,
        struct ipv6_addr *addr
        );

#endif
