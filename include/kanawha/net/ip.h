#ifndef __KANAWHA_NET__IP_H__
#define __KANAWHA_NET__IP_H__

#include <kanawha/types.h>
#include <kanawha/endian.h>
#include <kanawha/printk.h>
#include <kanawha/attribute.h>

#define IPV4_MINIMUM_PACKET_HEADER_SIZE (5*4)

struct __packed ipv4_raw_addr {
    uint8_t data[4];
};

struct __packed ipv6_raw_addr {
    be16_t data[8];
};

#define IPV4_PROT_ICMP  (1)     // Internet Control Message Protocol
#define IPV4_PROT_IGMP  (2)     // Internet Group Management Protocol
#define IPV4_PROT_TCP   (6)     // Transmission Control Protocol
#define IPV4_PROT_UDP   (17)    // User Datagram Protocol
#define IPV4_PROT_ENCAP (41)    // IPv6 encapsulation
#define IPV4_PROT_OSPF  (89)    // Open Shortest Path First
#define IPV4_PROT_SCTP  (132)   // Stream Control Transmission Protocol

struct __packed ipv4_pkt_hdr {
    uint8_t version_and_ihl;
    uint8_t ecn_and_dscp;
    be16_t total_length;
    be16_t identification;
    uint8_t flags_and_fragment_high;
    uint8_t fragment_low;
    uint8_t ttl;
    uint8_t protocol;
    be16_t checksum;
    struct ipv4_raw_addr src_addr;
    struct ipv4_raw_addr dst_addr;
};

ASSERT_TYPE_SIZE(struct ipv4_pkt_hdr, IPV4_MINIMUM_PACKET_HEADER_SIZE);

struct __packed ipv4_raw_packet {
    struct ipv4_pkt_hdr hdr;
    uint8_t data[];
};

struct ipv4_addr {
    union {
        uint32_t value;
        struct ipv4_raw_addr raw;
    };
};

#define IPV4_ADDR_LOOPBACK ({\
        struct ipv4_addr addr;\
        addr.raw.data[0] = 127;\
        addr.raw.data[1] = 0;\
        addr.raw.data[2] = 0;\
        addr.raw.data[3] = 1;\
        addr;\
        })
#define IPV4_ADDR_LOCAL_BROADCAST ({\
        struct ipv4_addr addr;\
        addr.raw.data[0] = 255;\
        addr.raw.data[1] = 255;\
        addr.raw.data[2] = 255;\
        addr.raw.data[3] = 255;\
        addr;\
        })

struct ipv6_addr {
    union {
        struct {
            uint64_t value_0;
            uint64_t value_1;
        };
        struct ipv6_raw_addr raw;
    };
};

static inline void
ipv4_pkt_hdr_set_version(
        struct ipv4_pkt_hdr *hdr,
        uint8_t version)
{
    hdr->version_and_ihl &= 0x0F;
    hdr->version_and_ihl |= ((version << 4) & 0xF0);
}
static inline void
ipv4_pkt_hdr_set_ihl(
        struct ipv4_pkt_hdr *hdr,
        uint8_t ihl)
{
    hdr->version_and_ihl &= 0xF0;
    hdr->version_and_ihl |= (ihl & 0x0F);
}
static inline uint16_t
ipv4_pkt_hdr_get_ihl(
        struct ipv4_pkt_hdr *hdr)
{
    return hdr->version_and_ihl & 0xF;
}
static inline void
ipv4_pkt_hdr_set_header_length(
        struct ipv4_pkt_hdr *hdr,
        uint8_t length)
{
    uint8_t ihl = (length / 4) + !!(length % 4);
    ipv4_pkt_hdr_set_ihl(hdr, ihl);
}
static inline uint16_t
ipv4_pkt_hdr_get_header_length(
        struct ipv4_pkt_hdr *hdr)
{
    uint16_t ihl = ipv4_pkt_hdr_get_ihl(hdr);
    return ihl * 4;
}
static inline void
ipv4_pkt_hdr_set_ecn(
        struct ipv4_pkt_hdr *hdr,
        uint8_t ecn)
{
    hdr->ecn_and_dscp &= 0xFC;
    hdr->ecn_and_dscp |= (ecn & 0x3);
}
static inline void
ipv4_pkt_hdr_set_dscp(
        struct ipv4_pkt_hdr *hdr,
        uint8_t dscp)
{
    hdr->ecn_and_dscp &= 0x3;
    hdr->ecn_and_dscp |= ((dscp << 2) & 0xFC);
}
static inline void
ipv4_pkt_hdr_set_total_length(
        struct ipv4_pkt_hdr *hdr,
        uint16_t len)
{
    hdr->total_length = htobe16(len);
}
static inline void
ipv4_pkt_hdr_set_identification(
        struct ipv4_pkt_hdr *hdr,
        uint16_t id)
{
    hdr->identification = htobe16(id);
}
static inline void
ipv4_pkt_hdr_set_flags(
        struct ipv4_pkt_hdr *hdr,
        uint8_t flags)
{
    hdr->flags_and_fragment_high &= 0x1F;
    hdr->flags_and_fragment_high |= ((flags << 5) & 0xE0);
}
static inline void
ipv4_pkt_hdr_set_fragment_offset(
        struct ipv4_pkt_hdr *hdr,
        uint16_t fragment_offset)
{
    hdr->flags_and_fragment_high &= 0xE0;
    hdr->flags_and_fragment_high |= ((fragment_offset >> 8) & 0x1F);
    hdr->fragment_low = (uint8_t)fragment_offset & 0xFF;
}
static inline void
ipv4_pkt_hdr_set_ttl(
        struct ipv4_pkt_hdr *hdr,
        uint8_t ttl)
{
    hdr->ttl = ttl;
}
static inline void
ipv4_pkt_hdr_set_protocol(
        struct ipv4_pkt_hdr *hdr,
        uint8_t prot)
{
    hdr->protocol = prot;
}
static inline void
ipv4_pkt_hdr_set_source(
        struct ipv4_pkt_hdr *hdr,
        struct ipv4_addr addr)
{
    hdr->src_addr = addr.raw;
}
static inline void
ipv4_pkt_hdr_set_destination(
        struct ipv4_pkt_hdr *hdr,
        struct ipv4_addr addr)
{
    hdr->dst_addr = addr.raw;
}
static inline void
ipv4_pkt_hdr_compute_checksum(
        struct ipv4_pkt_hdr *hdr)
{
    hdr->checksum = htobe16(0);

    be16_t *as_shorts = (uint16_t*)hdr;

    uint16_t header_len = ipv4_pkt_hdr_get_header_length(hdr);
    size_t num_shorts = header_len / 2;

    uint32_t sum = 0;
    for(size_t i = 0; i < num_shorts; i++) {
        sum += betoh16(as_shorts[i]);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    hdr->checksum = ~htobe16(sum);
}


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
