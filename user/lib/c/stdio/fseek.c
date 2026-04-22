
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"
#include "kanawha/sys-wrappers.h"

#include <stdio.h>

int
fseek(FILE *stream, long int offset, int whence)
{
    ssize_t res;

    flockfile(stream);

    // Drop all buffered data
    __elk_libc_internal__file_purge(stream);

    res = kanawha_sys_seek(stream->__fd, offset, whence);
    if(res < 0)
    {
        // TODO set errno
        funlockfile(stream);
        return -1;
    }

    funlockfile(stream);

    return 0;
}
