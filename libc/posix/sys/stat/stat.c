
#include <sys/stat.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

int
stat(
    const char *path,
    struct stat * buffer)
{
    int res;

    fd_t filedes;
    
    res = kanawha_sys_open(
            path,
            FILE_PERM_READ,
            0,
            &filedes);

    if(res) {
        // TODO set errno
        return -1;
    }

    res = fstat((int)filedes, buffer);
    if(res) {
        kanawha_sys_close(filedes);
        return -1;
    }

    kanawha_sys_close(filedes);
    return 0;
}

