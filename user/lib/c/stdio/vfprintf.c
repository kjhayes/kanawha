
#include "elk-libc-internal/doprnt.h"
#include <stdarg.h>
#include <stdio.h>

#define BUFLEN 0x1000

struct vfprintf_state {
    FILE *stream;
    size_t datalen;
    char buffer[BUFLEN];
};

static int
vfprintf_state_flush(
        struct vfprintf_state *state)
{
    ssize_t written = fwrite(state->buffer, state->datalen, 1, state->stream);
    if(written < 0) {
        return written;
    }
    state->datalen = 0;
    return 0;
}

static int
vfprintf_putchar(int c, void *_state)
{
    struct vfprintf_state *state = (struct vfprintf_state *)_state;
    if(state->datalen == BUFLEN || c == '\n') {
        int res;
        res = vfprintf_state_flush(state);
        if(res) {
            return EOF;
        }
    }
    state->buffer[state->datalen] = c;
    state->datalen++;
    return c;
}

int
vfprintf(FILE *restrict stream, const char *restrict format, va_list arg)
{
    int res;
    struct vfprintf_state state = {
        .stream = stream,
        .datalen = 0,
    };
    res = doprnt(vfprintf_putchar, &state, format, arg);
    int flush_res = vfprintf_state_flush(&state);
    if(flush_res) {
        return flush_res;
    }
    return res;
}
