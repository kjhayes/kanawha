#ifndef __ELK_LIBC_POSIX_ARPA_INET_H__
#define __ELK_LIBC_POSIX_ARPA_INET_H__

#include <inttypes.h>
#include <netinet/in.h>

uint32_t
htonl(uint32_t);
uint16_t
htons(uint16_t);
uint32_t
ntohl(uint32_t);
uint16_t
ntohs(uint16_t);

in_addr_t
inet_addr(const char *);
char *inet_ntoa(struct in_addr);
const char *
inet_ntop(int, const void *restrict, char *restrict, socklen_t);
int
inet_pton(int, const char *restrict, void *restrict);
int
inet_aton(const char *cp, struct in_addr *inp);

#endif
