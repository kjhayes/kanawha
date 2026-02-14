
#include <elk-libc-internal/__sFILE.h>
#include <elk-libc-internal/FILE.h>
#include <stdarg.h>
#include <stdio.h>
#include <elk-libc-internal/doscan.h>

static int
vfscanf_consumestr(
        size_t len,
        void *state)
{
    FILE *file = (FILE*)state;
    return __elk_libc_internal__file_consume(file, len);
}

static const char *
vfscanf_peekstr(
        size_t min_len,
        size_t max_len,
        void *state)
{
    FILE *file = (FILE*)state;
    return __elk_libc_internal__file_peekstr(file, min_len, max_len);
}

int
vfscanf(
        FILE * restrict stream,
        const char *restrict format,
        va_list arg)
{
    return doscan(
            vfscanf_consumestr,
            vfscanf_peekstr,
            stream,
            format,
            arg);
}

