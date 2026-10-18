
#include <kanawha/file.h>
#include <kanawha/syscall.h>

int
close(int fd)
{
    kanawha_sys_close((fd_t)fd);
}
