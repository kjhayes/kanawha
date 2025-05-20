
#include <stdarg.h>
#include <stdio.h>

int sprintf(char * restrict s, const char * restrict format, ...)
{
    va_list arg;
    int done;

    va_start(arg, format);
    done = vsnprintf(s, (size_t)(~0), format, arg);
    va_end(arg);

    return done;
}

