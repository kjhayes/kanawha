
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

#include "kanawha/sys-wrappers.h"

#include <stdlib.h>
#include <stdio.h>

int fclose(FILE *stream)
{
    struct __sFILE *file = (struct __sFILE*)stream;

    int res = kanawha_sys_close(
            file->__fd);
    if(res) {
        return EOF;
    }

    __elk_libc_internal__deinit_sFILE(file);
    free(file);

    return 0;
}

