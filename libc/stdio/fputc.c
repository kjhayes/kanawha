
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <stdio.h>
#include <string.h>

#undef fputc_unlocked
int fputc_unlocked(int i, FILE * restrict stream)
{
    ssize_t res;
    struct __sFILE *file = (struct __sFILE *)stream;

    char c = (char)i;

    res = kanawha_sys_write(
            file->__fd,
            &c,
            sizeof(char));
    if(res != 1) {
        // TODO set FILE error
        return EOF;
    }

    return c;
}

#undef fputc
int fputc(int i, FILE * restrict stream)
{
    int res;
    flockfile(stream);
    res = fputc_unlocked(i, stream);
    funlockfile(stream);
    return res;
}

