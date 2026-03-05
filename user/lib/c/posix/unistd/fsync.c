
#include <errno.h>
#include <kanawha/sys-wrappers.h>
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
