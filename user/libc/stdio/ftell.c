
#include "kanawha/sys-wrappers.h"
#include "elk-libc-internal/__sFILE.h"

#include <stdio.h>

long int ftell(FILE *stream)
{
    ssize_t offset =
        kanawha_sys_seek(
                stream->__fd,
                0UL,
                SEEK_CUR);
    if(offset < 0) {
        // TODO set errno
        return -1L;
    }

    return offset;
}

