
#include <sys/mman.h>
#include <errno.h>
#include <kanawha/syscall.h>

void *
mmap(void *addr,
     size_t length,
     int prot,
     int flags,
     int fd,
     off_t offset)
{
    int res;

    unsigned long sys_flags = prot | flags;

    void *where = addr;
    res = kanawha_sys_mmap(
            fd,
            offset,
            &where,
            length,
            sys_flags);
    if(res) {
        errno = res;
        return MAP_FAILED;
    } 
    return where;
}

