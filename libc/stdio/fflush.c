
#include "kanawha/sys-wrappers.h"
#include "elk-libc-internal/__sFILE.h"

#include <stdio.h>

int
fflush(FILE *stream)
{
    int res;

    res = kanawha_sys_flush(
            stream->__fd,
            0);
    if(res) {
        return res;
    }

    return 0;
}

