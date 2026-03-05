
#include <elk-libc-internal/DIR.h>
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

DIR *
fdopendir(int fd)
{
    int res;

    DIR *dir = __elk_libc_internal__alloc_DIR();
    if(dir == NULL)
    {
        errno = -ENOMEM;
        return NULL;
    }

    dir->fd = fd;

    res = kanawha_sys_dirbegin(fd);
    if(res)
    {
        if(res == -ENXIO)
        {
            // Empty directory
            dir->eod = 1;
        }
        else
        {
            __elk_libc_internal__free_DIR(dir);
            errno = res;
            return NULL;
        }
    }

    return dir;
}

DIR *
opendir(const char *path)
{
    int res;

    fd_t fd;
    res = kanawha_sys_open(path, FILE_PERM_READ, 0, &fd);
    if(res)
    {
        errno = res;
        return NULL;
    }

    DIR *dir = fdopendir(fd);
    if(dir == NULL)
    {
        // errno propogates
        return NULL;
    }

    return dir;
}
