
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/dofopen.h>

#include <kanawha/file.h>
#include <kanawha/syscall.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef fopen
FILE *
fopen(const char *restrict path, const char *restrict mode)
{
    int res;

    FILE *file = malloc(sizeof(FILE));
    if(file == NULL)
    {
        errno = -ENOMEM;
        return NULL;
    }
    memset(file, 0, sizeof(FILE));
    __elk_libc_internal__init_FILE(file);

    res = __elk_libc_internal__dofopen(path, mode, file);
    if(res)
    {
        __elk_libc_internal__deinit_FILE(file);
        free(file);
        errno = res;
        return NULL;
    }

    return (FILE *)file;
}
