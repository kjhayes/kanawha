
#include <errno.h>
#include <kanawha/syscall.h>
#include <unistd.h>

int
fsync(int filedes)
{
    int res;
    res = kanawha_sys_flush(filedes, 0);
    if(res)
    {
        errno = res;
        return -1;
    }
    return 0;
}
