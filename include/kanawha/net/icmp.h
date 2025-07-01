#ifndef __KANAWHA__NET_ICMP_H__
#define __KANAWHA__NET_ICMP_H__

#include <kanawha/net/ip.h>
#include <kanawha/endian.h>
#include <kanawha/types.h>

#include <kanawha/dev/net/ipv4.h>

#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8

struct icmp_pkt_hdr {
    uint8_t type;
    uint8_t code;
    be16_t checksum;
    be32_t roh;
};

static inline void
icmp_pkt_hdr_compute_checksum(
        struct icmp_pkt_hdr *hdr)
{
    hdr->checksum = 0;

    uint32_t sum = 0;
    sum += betoh16(((uint16_t*)hdr)[0]);
    sum += betoh16(((uint16_t*)hdr)[1]);
    sum += betoh16(((uint16_t*)hdr)[2]);
    sum += betoh16(((uint16_t*)hdr)[3]);
 
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    hdr->checksum = ~htobe16(sum);
}

int
ipv4_dev_send_icmp(
        struct ipv4_dev *dev,
        struct ipv4_addr src,
        struct ipv4_addr dst,
        uint8_t type,
        uint8_t code,
        uint32_t roh,
        void *data,
        size_t datalen);

int
ipv4_dev_send_icmp_ping(
        struct ipv4_dev *dev,
        struct ipv4_addr src,
        struct ipv4_addr dst
        );

#endif
