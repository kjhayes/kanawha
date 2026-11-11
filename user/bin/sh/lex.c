
#include "lex.h"
#include "token.h"
#include <errno.h>
#include <string.h>
#include <ctype.h>

struct lex_state {
    const char *cmdbuf;
    size_t buflen;
    size_t offset;
    struct token_list *list;
};

static inline int 
try_lex_whitespace(
        struct lex_state *state)
{
    char c = state->cmdbuf[state->offset];
    switch(c) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            state->offset++;
            break;
    }
}

static inline int
try_lex_operator(
        struct lex_state *state)
{
    int res;

    unsigned long operator_len = 0;
    token_type_t type;
    const char *value;

    size_t room = state->buflen - state->offset;

#define XCASE(__NAME, __STR, ...)\
    {\
        size_t len = strlen(__STR);\
        if((len <= room) && \
           (strncmp(__STR, \
                    state->cmdbuf + state->offset, \
                    len) == 0))\
        {\
            operator_len = len;\
            type = TOKEN_TYPE_##__NAME;\
            value = __STR;\
        }\
    }

    OPERATOR_TOKEN_XLIST(XCASE)

#undef XCASE

    if(operator_len > 0) {
        struct token *token = token_create(type);
        if(token == NULL) {
            return -ENOMEM;
        }
        res = token_set_value(token, value);
        if(res) {
            token_destroy(token);
            return res;
        }
        token_list_push_tail(state->list, token);
        state->offset += operator_len;
    }

    return 0;
}

static inline int
is_blob_char(char c)
{
    if(isalnum(c)) {
        return 1;
    }
    switch(c) {
        case '_':
        case '/':
        case '\\':
        case '.':
        case ':':
            return 1;
    }
    return 0;
}

static inline int
try_lex_blob(
        struct lex_state *state)
{
    int res;

    size_t len = 0;
    while(state->offset + len < state->buflen) {
        char c = state->cmdbuf[state->offset + len];
        if(!is_blob_char(c))
        {
            break;
        }
        len++;
    }

    if(len == 0) {
        return 0;
    }

    struct token *token = token_create(TOKEN_TYPE_BLOB);
    if(token == NULL) {
        return -ENOMEM;
    }

    res = token_setn_value(
            token,
            state->cmdbuf + state->offset,
            len);
    if(res) {
        token_destroy(token);
        return res;
    }

    token_list_push_tail(state->list, token);
    state->offset += len;

    return 0;
}

static inline int
try_lex_string(
        struct lex_state *state)
{
    int res;

    char close = '\0';
    char open = state->cmdbuf[state->offset];
    switch(open) {
        case '\"':
        case '\'':
            close = open;
            break;
        default:
            return 0;
    }

    size_t len = 1;

    int found_close = 0;
    while(state->offset + len < state->buflen) {
        char c = state->cmdbuf[state->offset + len];
        len++;
        if(c == close) {
            found_close = 1;
            break;
        }
    }

    if(!found_close) {
        return -EINVAL;
    }

    struct token *token = token_create(TOKEN_TYPE_STRING);
    if(token == NULL) {
        return -ENOMEM;
    }

    res = token_setn_value(
            token,
            state->cmdbuf + state->offset,
            len);
    if(res) {
        token_destroy(token);
        return res;
    }

    token_list_push_tail(state->list, token);
    state->offset += len;

    return 0;
}

int
lex_cmd(
        const char *_cmdbuf,
        size_t _buflen,
        struct token_list *_list)
{
    struct lex_state state = {
        .cmdbuf = _cmdbuf,
        .buflen = _buflen,
        .offset = 0,
        .list = _list,
    };

    while(state.offset < state.buflen) {
        size_t start_offset = state.offset;
        try_lex_whitespace(&state);
        if(start_offset != state.offset) {
            continue;
        }
        try_lex_operator(&state);
        if(start_offset != state.offset) {
            continue;
        }
        try_lex_blob(&state);
        if(start_offset != state.offset) {
            continue;
        }
        try_lex_string(&state);
        if(start_offset != state.offset) {
            continue;
        }

        return -EINVAL;
    }

    return 0;
}

