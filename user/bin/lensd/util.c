
#include "util.h"

#include <kanawha/syscall.h>
#include <stdio.h>

int
foreach_in_dir(
        const char *dir_path,
        int(*callback)(const char *path))
{
    int res;
    fd_t dir;
    res = kanawha_sys_open(
                dir_path,
                FILE_PERM_READ,
                0,
                &dir);
    if(res) {
        return res;
    }

    res = kanawha_sys_dirbegin(dir);
    if(res == 0) {
#define BUFLEN 0x100
        char namebuf[BUFLEN];
        char pathbuf[BUFLEN];

        while(1) {
            res = kanawha_sys_dirname(dir, namebuf, BUFLEN);
            if(res) {
                kanawha_sys_close(dir);
                return res;
            }
            namebuf[BUFLEN-1] = '\0';

            snprintf(pathbuf, BUFLEN, "%s/%s", dir_path, namebuf);
            pathbuf[BUFLEN-1] = '\0';

            res = (*callback)(pathbuf);
            if(res) {
                kanawha_sys_close(dir);
                return res;
            }

            res = kanawha_sys_dirnext(dir);
            if(res) {
                break;
            }
        }
#undef BUFLEN
    }

    kanawha_sys_close(dir);
    return 0;
}

