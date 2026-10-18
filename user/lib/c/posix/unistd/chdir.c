
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>
#include <unistd.h>

int
chdir(const char *path)
{
    int res;

    fd_t file;
    res = kanawha_sys_open(path, 0, 0, &file);
    if(res)
    {
        errno = res;
        return -1;
    }
    res = kanawha_sys_chwdir(file);
    if(res)
    {
        errno = res;
        return -1;
    }
    res = kanawha_sys_close(file);
    if(res)
    {
        errno = res;
        return -1;
    }

    return 0;
}
