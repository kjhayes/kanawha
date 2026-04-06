
#include "elk-libc-internal/__sFILE.h"
#include "kanawha/sys-wrappers.h"

#include <stdio.h>

long int
ftell(FILE *stream)
{
    flockfile(stream);

    size_t peeked = __elk_libc_internal__file_prefetch_buffered(stream);

    ssize_t offset = kanawha_sys_seek(stream->__fd, 0UL, SEEK_CUR);
    if(offset < 0)
    {
        // TODO set errno
        funlockfile(stream);
        return -1L;
    }

    offset -= peeked;

    funlockfile(stream);

    return offset;
}
