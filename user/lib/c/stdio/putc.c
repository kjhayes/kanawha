
#include <elk-libc-internal/FILE.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>

#include <stdio.h>
#include <string.h>

#undef putc_unlocked
int
putc_unlocked(int i, FILE *restrict stream)
{
    ssize_t res;

    char c = (char)i;

    res = kanawha_sys_write(stream->__fd, &c, sizeof(char));
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
