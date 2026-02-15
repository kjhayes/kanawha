
#include <stdio.h>
#include <stdarg.h>

int
sscanf(
        const char * restrict s,
        const char * restrict format,
        ...)
{
    int done;
    va_list arg;
    va_start(arg, format);
    done = vsscanf(s, format, arg);
    va_end(arg);
    return done;
}

