#ifndef __ELK_LIBC_POSIX_NETINET_IN_H__
#define __ELK_LIBC_POSIX_NETINET_IN_H__

#include <inttypes.h>
#include <sys/socket.h>

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t  s_addr;
};

struct in6_addr {
    uint8_t s6_addr[16];
};

struct sockaddr_in {
    sa_family_t    sin_family;   //AF_INET. 
    in_port_t      sin_port;     //Port number. 
    struct in_addr sin_addr;     //IP address. 
};

struct sockaddr_in6 {
    sa_family_t     sin6_family;    //AF_INET6. 
    in_port_t       sin6_port;      //Port number. 
    uint32_t        sin6_flowinfo;  //IPv6 traffic class and flow information. 
    struct in6_addr sin6_addr;      //IPv6 address. 
    uint32_t        sin6_scope_id;  //Set of interfaces for a scope. 
};

extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

struct ipv6_mreq {
    struct in6_addr  ipv6mr_multiaddr;  //IPv6 multicast address. 
    unsigned         ipv6mr_interface;  //Interface index. 
};

#define IPPROTO_IP   (1)
#define IPPROTO_IPV6 (2)
#define IPPROTO_ICMP (3)
#define IPPROTO_RAW  (4)
#define IPPROTO_TCP  (5)
#define IPPROTO_UDP  (6)

#define INADDR_ANY       (0x0UL)
#define INADDR_BROADCAST (0xFFFFFFFFUL)

#define INET_ADDRSTRLEN (16)

#endif
