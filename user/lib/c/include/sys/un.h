#ifndef __ELK_LIBC_POSIX_SYS__UN_H__
#define __ELK_LIBC_POSIX_SYS__UN_H__

#include <sys/socket.h>

struct sockaddr_un
{
    sa_family_t sun_family; // Address family.
    char sun_path[64];      // Socket pathname.
};

#endif
