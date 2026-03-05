
#include <elk-libc-internal/__sFILE.h>
#include <errno.h>

int
__elk_libc_internal__dofopen(const char *restrict path,
                             const char *restrict mode,
                             struct __sFILE *file)
{
    unsigned long access_flags = 0;
    unsigned long mode_flags = 0;

    int can_create = 0;
    int truncate = 0;
    int append = 0;

    if(strchr(mode, 'r') != NULL)
    {
        access_flags |= FILE_PERM_READ;
    }

    if(strchr(mode, 'w') != NULL)
    {
        can_create = 1;
        truncate = 1;
        access_flags |= FILE_PERM_WRITE;
    }

    if(strchr(mode, 'a') != NULL)
    {
        can_create = 1;
        append = 1;
        access_flags |= FILE_PERM_WRITE;
    }

    if(strchr(mode, '+') != NULL)
    {
        access_flags |= FILE_PERM_READ;
        access_flags |= FILE_PERM_WRITE;
    }

    if(truncate)
    {
        mode_flags |= FILE_MODE_OPEN_TRUNC;
    }

    int res = kanawha_sys_open(path, access_flags, mode_flags, &file->__fd);
    if(res == -ENXIO && can_create)
    {

        size_t pathlen = strlen(path);
        char *path_copy = malloc(pathlen + 1);
        if(path_copy == NULL)
        {
            return -ENOMEM;
        }
        strncpy(path_copy, path, pathlen);
        path_copy[pathlen] = '\0';

        char *dirpath;
        char *filename = strrchr(path_copy, '/');
        if(filename == NULL)
        {
            dirpath = "";
            filename = path_copy;
        }
        else
        {
            dirpath = path_copy;
            filename[0] = '\0';
            filename = filename + 1;
            if(strlen(dirpath) == 0)
            {
                dirpath = "/";
            }
        }

        fd_t dir;
        res = kanawha_sys_open(dirpath,
                               FILE_PERM_READ | FILE_PERM_WRITE,
                               0,
                               &dir);
        if(res)
        {
            free(path_copy);
            return res;
        }

        res = kanawha_sys_mkfile(dir, filename, 0);
        if(res)
        {
            free(path_copy);
            return res;
        }
        free(path_copy);

        res = kanawha_sys_flush(dir, 0);
        if(res)
        {
            // Weird but leave it alone
        }

        res = kanawha_sys_close(dir);
        if(res)
        {
            // Weird but leave it alone
        }

        res = kanawha_sys_open(path, access_flags, mode_flags, &file->__fd);
        if(res)
        {
            return res;
        }
    }
    else if(res)
    {
        return res;
    }

    return 0;
}
