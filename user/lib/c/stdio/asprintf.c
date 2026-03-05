
#include <stdarg.h>
#include <stdio.h>

int
asprintf(char **out, const char *restrict format, ...)
{
    va_list arg;
    int done;

    va_start(arg, format);
    done = vasprintf(out, format, arg);
    va_end(arg);

    return done;
}
