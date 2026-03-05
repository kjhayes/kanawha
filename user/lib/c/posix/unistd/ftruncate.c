
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <unistd.h>

int
ftruncate(int filedes, off_t offset)
{
    int res;
    res = kanawha_sys_resize(filedes, offset, 0);
    if(res)
    {
        errno = res;
        return -1;
    }
    return 0;
}
