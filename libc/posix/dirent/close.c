
#include <elk-libc-internal/DIR.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

int
closedir(DIR *dir)
{
    int res;

    res = kanawha_sys_close(dir->fd);
    if(res) {
        // TODO set errno
        return -1;
    }

    __elk_libc_internal__free_DIR(dir);

    return 0;
}

