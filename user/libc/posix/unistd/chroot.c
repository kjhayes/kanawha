
#include <unistd.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

int
chroot(const char *path)
{
    fd_t file;

    int res;
    res = kanawha_sys_open(
            path,
            FILE_PERM_READ,
            0,
            &file);
    if(res) {
        // TODO set errno
        return -1;
    }

    res = kanawha_sys_chroot(file);
    if(res) {
        // TODO set errno
        return res;
    }

    kanawha_sys_close(file);

    return 0;
}
