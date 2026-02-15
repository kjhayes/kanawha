
#include "kanawha/sys-wrappers.h"
#include "elk-libc-internal/__sFILE.h"

#include <stdio.h>

int
fseek(
        FILE *stream,
        long int offset,
        int whence)
{
    ssize_t res;

    res = kanawha_sys_seek(
            stream->__fd,
            offset,
            whence);
    if(res < 0) {
        // TODO set errno
        return -1;
    }

    return 0;
}

