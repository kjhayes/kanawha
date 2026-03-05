
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <unistd.h>

int
access(const char *path, int flags)
{
    int res;

    int mode_flags = 0;
    int access_flags = 0;

    // TODO deal with F_OK flag

    if(flags & R_OK)
    {
        access_flags |= FILE_PERM_READ;
    }
    if(flags & W_OK)
    {
        access_flags |= FILE_PERM_WRITE;
    }
    if(flags & X_OK)
    {
        access_flags |= FILE_PERM_EXEC;
    }

    fd_t filedes;

    res = kanawha_sys_open(path, access_flags, mode_flags, &filedes);
    if(res)
    {
        errno = res;
        return -1;
    }

    kanawha_sys_close(filedes);

    return 0;
}
