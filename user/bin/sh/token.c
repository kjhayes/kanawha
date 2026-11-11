
#include "token.h"
#include <elk/list.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct token {
    token_type_t type;
    char *value;

    struct token_list *list;
    list_node_t list_node;
};

struct token_list {
    list_t tokens;
};

DEFINE_CUSTOM_LIST(
        _token_list,
        struct token_list,
        tokens,
        struct token,
        list_node);

static int
_token_deattach(
        struct token *token)
{
    if(token->list) {
        _token_list_remove(token->list, token);
        token->list = NULL;
    }
    return 0;
}

static int
_token_attach_tail(
        struct token *token,
        struct token_list *list)
{
    _token_deattach(token);
    token->list = list;
    _token_list_push_tail(list, token);
    return 0;
}

struct token *
token_create(
        token_type_t type)
{
    struct token *token = malloc(sizeof(*token));
    if(token == NULL) {
        return NULL;
    }
    token->type = type;
    token->value = NULL;
    token->list = NULL;
    return token;
}
int
token_destroy(
        struct token *token)
{
    _token_deattach(token);
    free(token);
    return 0;
}

struct token_list *
token_list_create(void)
{
    struct token_list *list = malloc(sizeof(*list));
    if(list == NULL) {
        return NULL;
    }
    _token_list_init(list);
    return list;
}
int
token_list_destroy(
        struct token_list *list)
{
    while(1) {
        struct token *token = _token_list_begin(list);
        if(token == NULL) {
            break;
        }
        token_destroy(token); 
    }
    free(list);
    return 0;
}

int
token_list_count(
        struct token_list *l)
{
    return _token_list_count(l);
}
struct token *
token_list_begin(
        struct token_list *l)
{
    return _token_list_begin(l);
}
struct token *
token_list_next(
        struct token_list *l,
        struct token *t)
{
    return _token_list_next(l,t);
}
int
token_list_push_tail(
        struct token_list *l,
        struct token *t)
{
    _token_deattach(t);
    t->list = l;
    _token_list_push_tail(l,t);
    return 0;
}
int
token_list_push_head(
        struct token_list *l,
        struct token *t)
{
    _token_deattach(t);
    t->list = l;
    _token_list_push_head(l,t);
    return 0;
}
int
token_list_remove(
        struct token_list *l,
        struct token *t)
{
    if(t->list != l) {
        return -EINVAL;
    }
    return _token_deattach(t);
}

token_type_t
token_get_type(
        struct token *token)
{
    return token->type;
}
const char *
token_get_value(
        struct token *token)
{
    if(token->value) {
        return token->value;
    } else {
        return "";
    }
}
int
token_set_value(
        struct token *token,
        const char *value)
{
    char *new = strdup(value);
    if(new == NULL) {
        return -ENOMEM;
    }
    char *old = token->value;
    token->value = new;
    free(old);
    return 0;
}
int
token_setn_value(
        struct token *token,
        const char *value,
        size_t len)
{
    char *new = strndup(value, len);
    if(new == NULL) {
        return -ENOMEM;
    }
    char *old = token->value;
    token->value = new;
    free(old);
    return 0;
}

