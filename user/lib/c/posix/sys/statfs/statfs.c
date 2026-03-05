
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <sys/statfs.h>

int
statfs(const char *path, struct statfs *buf)
{
    int res;

    fd_t filedes;

    res = kanawha_sys_open(path, FILE_PERM_READ, 0, &filedes);

    if(res)
    {
        // TODO set errno
        return -1;
    }

    res = fstatfs((int)filedes, buf);
    if(res)
    {
        kanawha_sys_close(filedes);
        return -1;
    }

    kanawha_sys_close(filedes);
    return 0;
}
