
#include <stdio.h>
#include <elk-libc-internal/__sFILE.h>
#include <elk-libc-internal/dofopen.h>

FILE *
fdopen(
    int filedes,
    const char * restrict mode)
{
    int res;

    struct __sFILE *file = malloc(sizeof(struct __sFILE));
    if(file == NULL) {
        errno = -ENOMEM;
        return NULL;
    }
    memset(file, 0, sizeof(struct __sFILE));
    __elk_libc_internal__init_sFILE(file);

    file->__fd = filedes;

    return file;
}

