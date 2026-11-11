
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/dofopen.h>
#include <stdio.h>

FILE *
fdopen(int filedes, const char *restrict mode)
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

    file->__fd = filedes;

    return file;
}
