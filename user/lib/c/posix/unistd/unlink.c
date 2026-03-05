
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
unlink(const char *path)
{
    int res;

    char *slash = strrchr(path, '/');

    fd_t dir;

    if(slash == NULL)
    {
        // This is just a file name
        res = kanawha_sys_open("", FILE_PERM_WRITE, 0, &dir);
        if(res)
        {
            errno = res;
            return -1;
        }
    }
    else
    {
        char *split_buffer = strdup(path);
        if(split_buffer == NULL)
        {
            errno = -ENOMEM;
            return -1;
        }

        char *buffer_slash = strrchr(split_buffer, '/');
        *buffer_slash = '\0';

        res = kanawha_sys_open(split_buffer, FILE_PERM_WRITE, 0, &dir);
        free(split_buffer);
        if(res)
        {
            errno = res;
            return -1;
        }

        path = slash + 1;
    }

    res = kanawha_sys_unlink(dir, path);
    if(res)
    {
        errno = res;
        return -1;
    }

    return 0;
}
