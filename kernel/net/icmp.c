
#include <kanawha/net/icmp.h>
#include <kanawha/net/ip.h>
#include <kanawha/endian.h>
#include <kanawha/types.h>

int
ipv4_dev_send_icmp(
        struct ipv4_dev *dev,
        struct ipv4_addr src,
        struct ipv4_addr dst,
        uint8_t type,
        uint8_t code,
        uint32_t roh,
        void *data,
        size_t datalen)
{
    int res;

    if(datalen != 0) {
        return -EUNIMPL;
    }

    struct ipv4_packet *pkt;
    pkt = ipv4_dev_alloc_packet(dev, sizeof(struct ipv4_raw_packet) + sizeof(struct icmp_pkt_hdr), 0);
    if(pkt == NULL) {
        return -ENOMEM;
    }

    struct ipv4_pkt_hdr *hdr = &pkt->data->hdr;
    ipv4_pkt_hdr_set_header_length(hdr, sizeof(*hdr));
    ipv4_pkt_hdr_set_total_length(hdr, sizeof(struct ipv4_raw_packet) + sizeof(struct icmp_pkt_hdr));

    ipv4_pkt_hdr_set_version(hdr, 4);
    ipv4_pkt_hdr_set_ecn(hdr, 0);
    ipv4_pkt_hdr_set_dscp(hdr, 0);
    ipv4_pkt_hdr_set_fragment_offset(hdr, 0);
    ipv4_pkt_hdr_set_ttl(hdr, 64);
    ipv4_pkt_hdr_set_protocol(hdr, IPV4_PROT_ICMP);

    ipv4_pkt_hdr_set_source(hdr, src);
    ipv4_pkt_hdr_set_destination(hdr, dst);

    ipv4_pkt_hdr_compute_checksum(hdr);

    struct icmp_pkt_hdr *icmp_hdr = (void*)pkt->data->data;
    icmp_hdr->type = type;
    icmp_hdr->code = code; 
    icmp_hdr->roh = htobe32(roh);
    icmp_pkt_hdr_compute_checksum(icmp_hdr);

    res = ipv4_packet_send(pkt);

    int drop_res = ipv4_packet_drop(pkt);
    if(drop_res) {
        wprintk("Failed to drop IPv4 packet during ICMP send! (err=%s)\n",
                errnostr(drop_res));
    }

    return res;
}

int
ipv4_dev_send_icmp_ping(
        struct ipv4_dev *dev,
        struct ipv4_addr src,
        struct ipv4_addr dst
        )
{
    return ipv4_dev_send_icmp(
            dev,
            src,
            dst,
            ICMP_TYPE_ECHO_REQUEST,
            0,
            0,
            NULL,
            0);
}

