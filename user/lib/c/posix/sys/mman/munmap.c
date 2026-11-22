
#include <sys/mman.h>
#include <errno.h>
#include <kanawha/syscall.h>

int
munmap(void *addr,
       size_t length)
{
    int res;
    res = kanawha_sys_munmap(addr);
    if(res) {
        errno = res;
        return -1;
    }
    return 0;
}
