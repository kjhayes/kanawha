
#include <unistd.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

int
chdir(const char *path)
{
    int res;

    fd_t file;
    res = kanawha_sys_open(
            path,
            0,
            0,
            &file);
    if(res) {
        // TODO set errno
        return -1;
    }
    res = kanawha_sys_chwdir(file);
    if(res) {
        // TODO set errno
        return -1;
    }
    res = kanawha_sys_close(file);
    if(res) {
        // TODO set errno
        return -1;
    }

    return 0;
}

