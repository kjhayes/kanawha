
#include <stdarg.h>
#include <stdio.h>

int
fscanf(
        FILE * restrict stream,
        const char * restrict format,
        ...)
{
    int done;
    va_list arg;
    va_start(arg, format);
    done = vfscanf(stream, format, arg);
    va_end(arg);
    return done;
}

