
#include <stdarg.h>
#include <stdio.h>
#include "elk-libc-internal/doprnt.h"

static int
vfprintf_putchar(int c, void *state)
{
    FILE *stream = (FILE*)state;
    return fputc(c, stream);
}

int
vfprintf(
        FILE * restrict stream,
        const char * restrict format,
        va_list arg)
{
    return doprnt(
            vfprintf_putchar,
            stream,
            format,
            arg);
}

