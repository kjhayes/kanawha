
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include "elk-libc-internal/doprnt.h"

struct vsnprintf_state {
    char *buffer;
    size_t room_left;
    size_t written;
};

static int
vsnprintf_putchar(int c, void *_state)
{
    struct vsnprintf_state *state = _state;

    if(state->room_left > 1) {
        *state->buffer = c;
        state->buffer++;
        state->room_left--;
        state->written++;
        return 0;
    }
    else if(state->room_left == 1) {
        *state->buffer = '\0';
        state->room_left = 0;
        // don't include '\0' in written
        return 0;
    } else {
        // No error has actually occurred but we'd rather doprnt end early
        // if we have a small buffer and a long string
        return -1;
    }
}


int vsnprintf(char * restrict s, size_t n, const char * restrict format, va_list arg)
{
    struct vsnprintf_state state;
    state.buffer = s;
    state.room_left = n;
    state.written = 0;

    doprnt(
        vsnprintf_putchar,
        &state,
        format,
        arg);

    if(state.room_left > 0) {
        // If we had extra room, append the null terminator
        *state.buffer = '\0';
    }

    return (int)state.written;
}

