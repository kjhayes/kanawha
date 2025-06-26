
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>

ssize_t
read(
    int filedes,
    void *buf,
    size_t nbyte)
{
    ssize_t res;

    res = kanawha_sys_read(filedes, buf, nbyte);
    if(res < 0) {
        errno = res;
        return -1;
    }

    return res; // number of bytes read
}

ssize_t
pread(
    int filedes,
    void *buf,
    size_t nbyte,
    off_t offset)
{
    ssize_t cur_offset = kanawha_sys_seek(filedes, 0, SEEK_CUR);
    if(cur_offset < 0) {
        // TODO set errno
        return -1;
    }

    ssize_t res = read(filedes, buf, nbyte);
    if(res < 0) {
        kanawha_sys_seek(filedes, cur_offset, SEEK_SET);
        return -1;
    }

    kanawha_sys_seek(filedes, cur_offset, SEEK_SET);
    return 0;
}

