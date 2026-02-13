#ifndef __ELK_LIBC_POSIX__NETDB_H__
#define __ELK_LIBC_POSIX__NETDB_H__

#include <inttypes.h>
#include <sys/socket.h>

struct hostent
{
    char  *h_name;      //Official name of the host.
    char **h_aliases;   //A pointer to an array of pointers to alternative host names,
                        //terminated by a null pointer.
    int    h_addrtype;  //Address type.
    int    h_length;    //The length, in bytes, of the address.
    char **h_addr_list; //A pointer to an array of pointers to network addresses (in
                        //network byte order) for the host, terminated by a null pointer.
};

struct netent
{
    char  *n_name;      //Official, fully-qualified (including the domain) name of the host.
    char **n_aliases;   //A pointer to an array of pointers to alternative network names,
                        //terminated by a null pointer.
    int    n_addrtype;  //The address type of the network.
    uint32_t n_net;     //The network number, in host byte order.
};

struct protoent
{
    char  *p_name;      //Official name of the protocol.
    char **p_aliases;   //A pointer to an array of pointers to alternative protocol names,
                        //terminated by a null pointer.
    int    p_proto;     //The protocol number.
};

struct servent
{
    char  *s_name;      //Official name of the service.
    char **s_aliases;   //A pointer to an array of pointers to alternative service names,
                        //terminated by a null pointer.
    int    s_port;      //The port number at which the service resides, in network byte order.
    char  *s_proto;     //The name of the protocol to use when contacting the service.
};

#define IPPORT_RESERVED (1ULL<<15)

extern int h_errno;

#define HOST_NOT_FOUND (1)
#define NO_DATA        (2)
#define NO_RECOVERY    (3)
#define TRY_AGAIN      (4)

void             endhostent(void);
void             endnetent(void);
void             endprotoent(void);
void             endservent(void);
struct hostent  *gethostbyaddr(const void *addr, size_t len, int type);
struct hostent  *gethostbyname(const char *name);
struct hostent  *gethostent(void);
struct netent   *getnetbyaddr(uint32_t net, int type);
struct netent   *getnetbyname(const char *name);
struct netent   *getnetent(void);
struct protoent *getprotobyname(const char *name);
struct protoent *getprotobynumber(int proto);
struct protoent *getprotoent(void);
struct servent  *getservbyname(const char *name, const char *proto);
struct servent  *getservbyport(int port, const char *proto);
struct servent  *getservent(void);
void             sethostent(int stayopen);
void             setnetent(int stayopen);
void             setprotoent(int stayopen);
void             setservent(int stayopen);

void herror(const char *s);
const char *hstrerror(int err);

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

#define AI_V4MAPPED    (1ULL<<0)
#define AI_ADDRCONFIG  (1ULL<<1)
#define AI_NUMERICHOST (1ULL<<2)
#define AI_PASSIVE     (1ULL<<3)
#define AI_NUMERICSERV (1ULL<<4)
#define AI_CANONNAME   (1ULL<<5)
#define AI_ALL         (1ULL<<6)

int getaddrinfo(const char *restrict node,
                const char *restrict service,
                const struct addrinfo *restrict hints,
                struct addrinfo **restrict res);

void freeaddrinfo(struct addrinfo *res);

#define NI_NAMEREQD    (1ULL<<0)
#define NI_DGRAM       (1ULL<<1)
#define NI_NOFQDN      (1ULL<<2)
#define NI_NUMERICHOST (1ULL<<3)
#define NI_NUMERICSERV (1ULL<<4)

int getnameinfo(const struct sockaddr *restrict addr,
                socklen_t addrlen,
                char *host,
                socklen_t hostlen,
                char *serv,
                socklen_t servlen,
                int flags);

#define EAI_ADDRFAMILY (1)
#define EAI_AGAIN      (2)
#define EAI_BADFLAGS   (3)
#define EAI_FAIL       (4)
#define EAI_FAMILY     (5)
#define EAI_MEMORY     (6)
#define EAI_NODATA     (7)
#define EAI_NONAME     (8)
#define EAI_SERVICE    (9)
#define EAI_SOCKTYPE   (10)
#define EAI_SYSTEM     (11)

const char *gai_strerror(int errcode);

#endif
