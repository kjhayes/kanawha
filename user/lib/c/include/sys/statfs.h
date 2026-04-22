#ifndef __ELK_LIBC_POSIX_SYS__STATFS_H__
#define __ELK_LIBC_POSIX_SYS__STATFS_H__

#include <inttypes.h>

struct statfs
{
    unsigned int f_type;
    unsigned int f_bsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    uint32_t f_fsid;
    unsigned int f_namelen;
    unsigned int f_frsize;
    unsigned int f_flags;
};

int
statfs(const char *path, struct statfs *buf);
int
fstatfs(int fd, struct statfs *buf);

#endif
