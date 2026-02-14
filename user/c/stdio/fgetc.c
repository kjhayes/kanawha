
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <stdio.h>
#include <assert.h>

#undef fgetc_unlocked
int fgetc_unlocked(FILE *stream)
{
    struct __sFILE *file = (struct __sFILE *)stream;

    assert(file != NULL);

    return __elk_libc_internal__file_getc(file);
}

#undef fgetc
int fgetc(FILE *stream)
{
    int res;
    flockfile(stream);
    res = fgetc_unlocked(stream);
    funlockfile(stream);
    return res;
}

