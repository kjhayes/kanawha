#ifndef __ELK_LIBC_POSIX_SYS__SOCKET_H__
#define __ELK_LIBC_POSIX_SYS__SOCKET_H__

#include <stdint.h>
#include <stddef.h>
#include <elk-libc-internal/ssize_t.h>

typedef unsigned long socklen_t;
typedef unsigned long sa_family_t;

struct sockaddr {
    sa_family_t   sa_family;  //address family
    char          sa_data[];  //socket address (variable-length data)
};

struct msghdr
{
    void         *msg_name;        //optional address
    socklen_t     msg_namelen;     //size of address
    struct iovec *msg_iov;         //scatter/gather array
    int           msg_iovlen;      //members in msg_iov
    void         *msg_control;     //ancillary data, see below
    socklen_t     msg_controllen;  //ancillary data buffer len
    int           msg_flags;       //flags on received message
};

struct cmsghdr
{
    socklen_t     cmsg_len;        //data byte count, including the cmsghdr
    int           cmsg_level;      //originating protocol
    int           cmsg_type;       //protocol-specific type
};

struct linger
{
    int         l_onoff;   //indicates whether linger option is enabled
    int         l_linger;  //linger time, in seconds
};


#define SOCK_DGRAM     (1)
#define SOCK_STREAM    (2)
#define SOCK_SEQPACKET (3)
#define SOCK_RAW       (4)
#define SOCK_RDM       (5)

#define SO_ACCEPTCONN (1)
#define SO_BROADCAST  (2)
#define SO_DEBUG      (3)
#define SO_DONTROUTE  (4)
#define SO_ERROR      (5)
#define SO_KEEPALIVE  (6)
#define SO_LINGER     (7)
#define SO_OOBINLINE  (8)
#define SO_RCVBUF     (9)
#define SO_RCVLOWAT   (10)
#define SO_RCVTIMEO   (11)
#define SO_REUSEADDR  (12)
#define SO_SNDBUF     (13)
#define SO_SNDLOWAT   (14)
#define SO_SNDTIMEO   (15)
#define SO_TYPE       (16)

#define MSG_CTRUNC    (1)
#define MSG_DONTROUTE (2)
#define MSG_EOR       (3)
#define MSG_OOB       (4)
#define MSG_PEEK      (5)
#define MSG_TRUNC     (6)
#define MSG_WAITALL   (7)

#define AF_UNSPEC    (0)
#define AF_UNIX      (1)
#define AF_INET      (2)
#define AF_AX25      (3)
#define AF_IPX       (4)
#define AF_APPLETALK (5)
#define	AF_NETROM    (6)
#define AF_BRIDGE    (7)
#define AF_AAL5      (8)
#define AF_X25       (9)
#define AF_INET6     (10)
#define AF_MAX       (11)

#define SHUT_RD   (0b01)
#define SHUT_WR   (0b10)
#define SHUT_RDWR (0b11)

#define SOL_SOCKET (1)

int accept(int socket, struct sockaddr *address,
        socklen_t *address_len);
int bind(int socket, const struct sockaddr *address,
        socklen_t address_len);
int connect(int socket, const struct sockaddr *address,
        socklen_t address_len);
int getpeername(int socket, struct sockaddr *address,
        socklen_t *address_len);
int getsockname(int socket, struct sockaddr *address,
        socklen_t *address_len);
int getsockopt(int socket, int level, int option_name,
        void *option_value, socklen_t *option_len);
int listen(int socket, int backlog);
ssize_t recv(int socket, void *buffer, size_t length, int flags);
ssize_t recvfrom(int socket, void *buffer, size_t length,
        int flags, struct sockaddr *address, socklen_t *address_len);
ssize_t recvmsg(int socket, struct msghdr *message, int flags);
ssize_t send(int socket, const void *message, size_t length, int flags);
ssize_t sendmsg(int socket, const struct msghdr *message, int flags);
ssize_t sendto(int socket, const void *message, size_t length, int flags,
        const struct sockaddr *dest_addr, socklen_t dest_len);
int setsockopt(int socket, int level, int option_name,
        const void *option_value, socklen_t option_len);
int shutdown(int socket, int how);
int socket(int domain, int type, int protocol);
int socketpair(int domain, int type, int protocol,
        int socket_vector[2]);

#endif
