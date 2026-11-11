
#include <elk-libc-internal/FILE.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>

#include <assert.h>
#include <stdio.h>

#undef fgetc_unlocked
int
fgetc_unlocked(FILE *stream)
{
    assert(stream != NULL);
    return __elk_libc_internal__file_getc(stream);
}

#undef fgetc
int
fgetc(FILE *stream)
{
    int res;
    flockfile(stream);
    res = fgetc_unlocked(stream);
    funlockfile(stream);
    return res;
}
