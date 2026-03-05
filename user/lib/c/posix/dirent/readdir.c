
#include <dirent.h>
#include <elk-libc-internal/DIR.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <sys/limits.h>

#define DIR_NAME_BUFLEN NAME_MAX

struct dirent *
readdir(DIR *dir)
{
    int res;

    if(dir->eod)
    {
        if(dir->dirent)
        {
            struct dirent *dirent = dir->dirent;
            dir->dirent = NULL;
            free(dirent);
        }
        return NULL;
    }

    if(dir->dirent == NULL)
    {
        dir->dirent = malloc(sizeof(*dir->dirent));
        if(dir->dirent == NULL)
        {
            res = -ENOMEM;
            return NULL;
        }
    }

    dir->dirent->d_ino = 0; // Don't provide the inode of a directory entry

    res = kanawha_sys_dirname(dir->fd, dir->dirent->d_name, DIR_NAME_BUFLEN);
    dir->dirent->d_name[DIR_NAME_BUFLEN - 1] = '\0';

    res = kanawha_sys_dirnext(dir->fd);
    if(res)
    {
        if(res == -ENXIO)
        {
            // This is the end of the directory
            dir->eod = 1;
        }
        else
        {
            errno = res;
            return NULL;
        }
    }

    return dir->dirent;
}
