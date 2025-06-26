
#include <stdio.h>
#include <elk-libc-internal/__sFILE.h>

int fsetpos(FILE *stream, const fpos_t *pos)
{
    int res;
    stream->eof = 0;
    res = __elk_libc_internal__file_purge(stream);
    if(res) {
        errno = res;
        return -1;
    }
    res = kanawha_sys_seek(stream->__fd, pos->__offset, SEEK_SET);
    if(res) {
        errno = res;
        return -1;
    }

    return 0;
}
