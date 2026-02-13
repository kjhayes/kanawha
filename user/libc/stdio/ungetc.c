
#include <stdio.h>
#include <elk-libc-internal/__sFILE.h>

int ungetc(int c, FILE *stream)
{
    int res;

    if(c == EOF) {
        return EOF;
    }

    res = __elk_libc_internal__file_ungetc(c, stream);
    if(res) {
        errno = res;
        return EOF;
    }

    return c;
}

