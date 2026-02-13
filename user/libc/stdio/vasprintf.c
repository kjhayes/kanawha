
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include "elk-libc-internal/doprnt.h"

#define VASPRINTF_INITIAL_SIZE 32
#define VASPRINTF_INCREASE_STEP 32

struct vasprintf_state
{
    char *buffer;
    size_t buffer_size;
    size_t head;
    size_t written;
};

static int
vasprintf_putchar(int c, void *_state)
{
    struct vasprintf_state *state = _state;

    if(state->head >= state->buffer_size) {
        void *tmp = realloc(state->buffer, state->buffer_size + VASPRINTF_INCREASE_STEP);
        if(tmp == NULL) {
            return -ENOMEM;
        }
        state->buffer = tmp;
        state->buffer_size += VASPRINTF_INCREASE_STEP;
    }

    state->buffer[state->head] = c;
    state->head++;
    state->written++;
    return 0;
}


int vasprintf(
        char ** restrict buffer_out,
        const char * restrict format,
        va_list arg)
{
    struct vasprintf_state state;

    state.buffer = malloc(VASPRINTF_INITIAL_SIZE);
    if(state.buffer == NULL) {
        return -ENOMEM;
    }
    state.buffer_size = VASPRINTF_INITIAL_SIZE;
    state.written = 0;
    state.head = 0;

    doprnt(
        vasprintf_putchar,
        &state,
        format,
        arg);

    if(state.buffer_size - state.written != 1) {
        void *tmp = realloc(state.buffer, state.written+1);
        if(tmp == NULL) {
            free(state.buffer);
            return -ENOMEM;
        }
        state.buffer = tmp;
    }
    state.buffer[state.written] = '\0';

    *buffer_out = state.buffer;

    return (int)state.written + 1;
}

