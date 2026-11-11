
#include "parse.h"
#include "cmd.h"
#include <errno.h>
#include <string.h>

struct parse_state
{
    struct token_list *tokens;
    struct token *head;
};

static inline int
parse_state_consume(
        struct parse_state *state,
        unsigned long amt)
{
    struct token *iter = state->head;
    while(amt > 0 && iter) {
        iter = token_list_next(state->tokens, iter);
        amt--;
    }
    if(amt != 0) {
        return -ENXIO;
    }
    state->head = iter;
    return 0;
}

struct cmd *
parse_cmd_invoke(
        struct parse_state *state)
{
    int res;
    struct token *head = state->head;
    if(head == NULL) {
        return NULL;
    }
    if(token_get_type(head) != TOKEN_TYPE_BLOB) {
        return NULL;
    }
    const char *exec_path = token_get_value(head);
    if(exec_path == NULL) {
        return NULL;
    }
    struct cmd_invoke *i = cmd_invoke_create(exec_path, 0);
    if(i == NULL) {
        return NULL;
    }

    res = parse_state_consume(state, 1);
    if(res) {
        cmd_invoke_destroy(i);
        return NULL;
    }

    while(state->head && token_get_type(state->head) == TOKEN_TYPE_BLOB) {
        const char *argvalue = token_get_value(state->head);
        if(argvalue == NULL) {
            cmd_invoke_destroy(i);
            return NULL;
        }
        res = cmd_invoke_push_arg(i, argvalue);
        if(res) {
            cmd_invoke_destroy(i);
            return NULL;
        }
        res = parse_state_consume(state, 1);
        if(res) {
            cmd_invoke_destroy(i);
            return NULL;
        }
    }

    return cmd_invoke_as_cmd(i);
}


struct cmd *
parse_cmd_blob(
        struct parse_state *state)
{
     int res;
    struct token *head = state->head;
    if(head == NULL) {
        return NULL;
    }
    if(token_get_type(head) != TOKEN_TYPE_BLOB) {
        return NULL;
    }
    const char *base = token_get_value(head);
    if(base == NULL) {
        return NULL;
    }

    return parse_cmd_invoke(state);
}

static inline struct cmd *
_parse_cmd(
        struct parse_state *state)
{
    struct cmd *cmd = NULL;
    while(state->head != NULL) {
        if(cmd != NULL) {
            cmd_destroy(cmd);
            return NULL;
        }
        switch(token_get_type(state->head)) {
            case TOKEN_TYPE_BLOB:
                cmd = parse_cmd_blob(state);
                break;
            default:
                return NULL;
        }
    }
    return cmd;
}

struct cmd *
parse_cmd(
        struct token_list *tokens)
{
    int res;

    struct parse_state state = {
        .tokens = tokens,
        .head = token_list_begin(tokens),
    };

    struct cmd *cmd;
    cmd = _parse_cmd(&state);
    if(cmd == NULL) {
        return NULL;
    }

    if(state.head != NULL) {
        cmd_destroy(cmd);
        return NULL;
    }

    return cmd;
}

