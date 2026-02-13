
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>
#include <elk-libc-internal/dofopen.h>

#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#undef fopen
FILE *fopen(
        const char * restrict path,
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

    res = __elk_libc_internal__dofopen(
            path,
            mode,
            file);
    if(res) {
        __elk_libc_internal__deinit_sFILE(file);
        free(file);
        errno = res;
        return NULL;
    }

    return (FILE*)file;
}

