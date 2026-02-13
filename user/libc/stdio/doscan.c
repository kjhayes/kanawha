
#include <elk-libc-internal/doscan.h>
#include <elk-libc-internal/__sFILE.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

struct doscan_state {
    // Inputs
    const char *fmt_iter;
    va_list args;

    // Return Value
    int num_matches;

    int running;

    // Constants
    void *priv_state;
    int(*consumestr)(size_t len, void *state);
    const char*(*peekstr)(size_t min_len, size_t max_len, void *state);
};

static inline int
doscan_fmt_getchar(
        struct doscan_state *state)
{
    char c = *state->fmt_iter;
    if(c != '\0') {
        state->fmt_iter++;
    }
    return c;
}

static inline int
doscan_consume(
        struct doscan_state *state,
        size_t len)
{
    return (state->consumestr)(len, state->priv_state);
}

static inline const char *
doscan_peekstr(
        struct doscan_state *state,
        size_t min_len,
        size_t max_len)
{
    return (state->peekstr)(min_len, max_len, state->priv_state);
}

static inline int
doscan_handle_escaped(
        struct doscan_state *state)
{
    int res;

    const char *peek;
    char *endptr;
    size_t diff;

    int *int_ptr;

    char conv_spec = doscan_fmt_getchar(state);

    switch(conv_spec) {
        case 'd':
            int_ptr = va_arg(state->args, int*);
            peek = doscan_peekstr(state, 1, 32);
            *int_ptr = strtol(peek, &endptr, 0);
            diff = endptr - peek;
            res = doscan_consume(state, diff);
            if(res) {
                return res;
            }
            break;
        default:
            return -EUNIMPL;
    }
    return 0;
}

int
doscan(
        int(*consumestr)(size_t len, void *state),
        const char*(*peekstr)(size_t min_len, size_t max_len, void *state),
        void *priv_state,
        const char *fmt,
        va_list args)
{
    int res;

    struct doscan_state state =
    {
        .fmt_iter = fmt,
        .priv_state = priv_state,
        .consumestr = consumestr,
        .peekstr = peekstr,

        .running = 1,

        .num_matches = 0,
    };
    va_copy(state.args, args);

    while(state.running && *state.fmt_iter) {
        char c = *state.fmt_iter;
        if(c == '%') {
            state.fmt_iter++;
            res = doscan_handle_escaped(&state);
            if(res) {
                state.running = 0;
                break;
            }
        } else {
            while(1) {
                const char *str = doscan_peekstr(&state, 1, 1);
                if(*str == c || isspace(*str)) {
                    if(*str == c) {
                        state.fmt_iter++;
                    }
                    res = doscan_consume(&state, 1);
                    if(res) {
                        state.running = 0;
                        break;
                    }
                } else {
                    state.running = 0;
                    break;
                }
            }
        }
    }

    va_end(state.args);
    return state.num_matches;
}

