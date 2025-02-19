
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#undef fgetc
int fgetc(FILE *stream)
{
    struct __sFILE *file = (struct __sFILE *)stream;

    assert(file != NULL);

    return __elk_libc_internal__file_getc(file);
}

