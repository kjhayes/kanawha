
#include <kanawha/dir.h>
#include <kanawha/errno.h>
#include <kanawha/file.h>
#include <kanawha/mount.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
for_each_file_under(const char *dir_path,
                    void (*callback)(int dir, const char *name, void *priv),
                    void *priv)
{
    int res;

    int dir;
    res = kanawha_sys_open(dir_path, FILE_PERM_READ, 0, &dir);
    if(res)
    {
        return res;
    }

    res = kanawha_sys_dirbegin(dir);
    if(res && res != -ENXIO)
    {
        kanawha_sys_close(dir);
        return res;
    }
    if(res == -ENXIO)
    {
        return 0;
    }

#define NAME_BUFLEN (256)
    char name_buf[NAME_BUFLEN];

    while(res == 0)
    {
        res = kanawha_sys_dirname(dir, name_buf, NAME_BUFLEN);
        if(res)
        {
            kanawha_sys_close(dir);
            return res;
        }

        name_buf[NAME_BUFLEN - 1] = '\0';

        (*callback)(dir, name_buf, priv);

        res = kanawha_sys_dirnext(dir);
        if(res && res != -ENXIO)
        {
            kanawha_sys_close(dir);
            return res;
        }
        if(res == -ENXIO)
        {
            break;
        }
    }

    return 0;
}
