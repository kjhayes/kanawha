
#include <kanawha/sys-wrappers.h>
#include <unistd.h>

off_t
lseek(
        int filedes,
        off_t offset,
        int whence)
{
    return kanawha_sys_seek(filedes, offset, whence);
}

