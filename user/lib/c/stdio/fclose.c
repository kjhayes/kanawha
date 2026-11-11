
#include <elk-libc-internal/FILE.h>

#include "kanawha/syscall.h"

#include <stdio.h>
#include <stdlib.h>

int
fclose(FILE *stream)
{
    FILE *file = (FILE *)stream;

    int res = kanawha_sys_close(file->__fd);
    if(res)
    {
        return EOF;
    }

    __elk_libc_internal__deinit_FILE(file);
    free(file);

    return 0;
}
