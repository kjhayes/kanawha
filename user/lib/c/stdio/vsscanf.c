
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>
#include <elk-libc-internal/doscan.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

struct vsscanf_state
{
    const char *str;
    const char *head;
};

static int
vsscanf_consumestr(size_t len, void *_state)
{
    struct vsscanf_state *state = _state;
    size_t chars_left = strlen(state->head);
    if(len > chars_left)
    {
        return -EINVAL;
    }
    state->head += len;
    return 0;
}

static const char *
vsscanf_peekstr(size_t min_len, size_t max_len, void *_state)
{
    struct vsscanf_state *state = _state;
    size_t chars_left = strlen(state->head);
    if(min_len < chars_left)
    {
        return NULL;
    }
    return state->head;
}

int
vsscanf(const char *restrict s, const char *restrict format, va_list arg)
{
    int res;

    struct vsscanf_state state = {
        .str = s,
        .head = 0,
    };

    res = doscan(vsscanf_consumestr, vsscanf_peekstr, &state, format, arg);

    return res;
}
