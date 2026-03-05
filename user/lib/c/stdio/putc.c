
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

#include <stdio.h>
#include <string.h>

#undef putc_unlocked
int
putc_unlocked(int i, FILE *restrict stream)
{
    ssize_t res;
    struct __sFILE *file = (struct __sFILE *)stream;

    char c = (char)i;

    res = kanawha_sys_write(file->__fd, &c, sizeof(char));
    if(res != 1)
    {
        // TODO set FILE error
        return EOF;
    }

    return c;
}

#undef putc
int
putc(int i, FILE *restrict stream)
{
    int res;
    flockfile(stream);
    res = putc_unlocked(i, stream);
    funlockfile(stream);
    return res;
}
