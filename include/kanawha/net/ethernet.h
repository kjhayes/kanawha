#ifndef __KANAWHA__NET_ETHERNET_H__
#define __KANAWHA__NET_ETHERNET_H__

#include <kanawha/assert.h>
#include <kanawha/endian.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>

#define ETH_MAC_ADDR_LEN 6
#define ETH_FRAME_HEADER_LEN 14

// "raw" Packed Structures

struct __packed eth_raw_mac_addr
{
    uint8_t data[ETH_MAC_ADDR_LEN];
};

ASSERT_TYPE_SIZE(struct eth_raw_mac_addr, ETH_MAC_ADDR_LEN);

struct __packed eth_frame_hdr
{
    struct eth_raw_mac_addr dst_addr;
    struct eth_raw_mac_addr src_addr;
    be16_t type;
};

struct eth_raw_frame
{
    struct eth_frame_hdr hdr;
    uint8_t data[];
};

ASSERT_TYPE_SIZE(struct eth_frame_hdr, ETH_FRAME_HEADER_LEN);

// "unpacked" Structures (hopefully faster)
struct eth_mac_addr
{
    union
    {
        uint64_t value;
        struct eth_raw_mac_addr raw;
    };
};

#define ETH_MAC_ADDR_BROADCAST                                                 \
    ({                                                                         \
        struct eth_mac_addr addr;                                              \
        addr.value = 0x0;                                                      \
        memset(addr.raw.data, 0xFF, 6);                                        \
        addr;                                                                  \
    })

// EtherType fields/comments adapted from
// (https://en.wikipedia.org/wiki/EtherType)
typedef enum
{
    ETH_TYPE_IPV4 = 0x0800,        // Internet Protocol Version 4 (IPv4)
    ETH_TYPE_ARP = 0x0806,         // Address Resolution Protocol
    ETH_TYPE_WAKE_ON_LAN = 0x0842, // Wake-on-LAN
    ETH_TYPE_SRP = 0x22EA,         // Stream Reservation Protocol
    ETH_TYPE_AVIP = 0x22F0,        // Audio Video Transport Protocol (AVTP)
    ETH_TYPE_IETF_TRILL = 0x22F3,  // IETF TRILL Protocol
    ETH_TYPE_DEC_MOP_RC = 0x6002,  // DEC MOP RC
    ETH_TYPE_DECNET_IV_DNA_ROUTING = 0x6003, // DECnet Phase IV, DNA Routing
    ETH_TYPE_DEC_LAT = 0x6004,               // DEC LAT
    ETH_TYPE_RARP = 0x8035,       // Reverse Address Resolution Protocol (RARP)
    ETH_TYPE_APPLE_TALK = 0x809B, // AppleTalk (EtherTalk)
    ETH_TYPE_LLC_PDU_IBM_SNA = 0x80D5, // LLC PDU (in particular, IBM SNA)
    ETH_TYPE_AARP = 0x80F3, // AppleTalk Address Resolution Protocol (AARP)
    ETH_TYPE_SLPP = 0x8102, // Simple Loop Prevention Protocol (SLPP)
    ETH_TYPE_VLACP =
        0x8103,            // Virtual Link Aggregation Control Protocol (VLACP)
    ETH_TYPE_IPX = 0x8137, // IPX
    ETH_TYPE_QNX_QNET = 0x8204,       // QNX Qnet
    ETH_TYPE_IPV6 = 0x86DD,           // Internet Protocol Version 6 (IPv6)
    ETH_TYPE_ETH_FLOW_PROT = 0x8808,  // Ethernet flow control
    ETH_TYPE_ETH_SLOW_PROT = 0x8809,  // Ethernet slow protocols
    ETH_TYPE_COBRANET = 0x8819,       // CobraNet
    ETH_TYPE_MPLS_UNICAST = 0x8847,   // MPLS unicast
    ETH_TYPE_MPLS_MULTICAST = 0x8848, // MPLS multicast
    ETH_TYPE_PPPOE_DISC = 0x8863,     // PPPoE Discovery Stage
    ETH_TYPE_PPPOE_SESS = 0x8864,     // PPPoE Session Stage
    ETH_TYPE_PROFINET = 0x8892,       // PROFINET Protocol
    ETH_TYPE_SCSI_OVER_ETH = 0x889A,  // HyperSCSI (SCSI over Ethernet)
    ETH_TYPE_ATA_OVER_ETH = 0x88A2,   // ATA over Ethernet
    ETH_TYPE_ETHERCAT = 0x88A4,       // EtherCAT Protocol
    ETH_TYPE_GOOSE = 0x88B8, // GOOSE (Generic Object Oriented Substation event)
    ETH_TYPE_GSE =
        0x88B9, // GSE (Generic Substation Events) Management Services
    ETH_TYPE_MAC_SEC = 0x88E5, // IEEE 802.1AE MAC security (MACsec)
    ETH_TYPE_PTP =
        0x88F7, // Precision Time Protocol (PTP) over IEEE 802.3 Ethernet
    ETH_TYPE_PRP = 0x88FB,       // Parallel Redundancy Protocol (PRP)
    ETH_TYPE_FCOE = 0x8906,      // Fibre Channel over Ethernet (FCoE)
    ETH_TYPE_FCOE_INIT = 0x8914, // FCoE Initialization Protocol
    ETH_TYPE_ROCE = 0x8915,      // RDMA over Converged Ethernet (RoCE)
    ETH_TYPE_TTE_CTRL = 0x891D,  // TTEthernet Protocol Control Frame (TTE)
    ETH_TYPE_HSR = 0x892F,       // High-availability Seamless Redundancy (HSR)
    ETH_TYPE_ECTP = 0x9000,      // Ethernet Configuration Testing Protocol
} eth_type_t;

int
dump_eth_mac_addr(printk_f *printer, struct eth_mac_addr *addr);

#endif
