#ifndef __KANAWHA__SH_TOKEN_H__
#define __KANAWHA__SH_TOKEN_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct token;
struct token_list;

#define OPERATOR_TOKEN_XLIST(X,...)\
X(OPEN_PAREN, "(", ##__VA_ARGS__)\
X(CLOSE_PAREN, ")", ##__VA_ARGS__)\
X(PIPE, "|", ##__VA_ARGS__)\
X(AMPERSAND, "&", ##__VA_ARGS__)\

#define OTHER_TOKEN_XLIST(X,...)\
X(BLOB, ##__VA_ARGS__)\
X(STRING, ##__VA_ARGS__)\

typedef enum {
#define XCASE(__NAME, ...)\
    TOKEN_TYPE_##__NAME,
    OPERATOR_TOKEN_XLIST(XCASE)
    OTHER_TOKEN_XLIST(XCASE)
#undef XCASE
} token_type_t;

static inline const char *
token_type_to_string(
        token_type_t type)
{
    switch(type) {
#define XCASE(__NAME, ...)\
        case TOKEN_TYPE_##__NAME: return "TOKEN_TYPE_"#__NAME;
    OPERATOR_TOKEN_XLIST(XCASE)
    OTHER_TOKEN_XLIST(XCASE)
#undef XCASE
    }
}

struct token *
token_create(
        token_type_t type);
int
token_destroy(
        struct token *);

struct token_list *
token_list_create(void);
int
token_list_destroy(
        struct token_list *);

int
token_list_count(
        struct token_list *);
struct token *
token_list_begin(
        struct token_list *);
struct token *
token_list_next(
        struct token_list *,
        struct token *);
int
token_list_push_tail(
        struct token_list *,
        struct token *);
int
token_list_push_head(
        struct token_list *,
        struct token *);
int
token_list_remove(
        struct token_list *,
        struct token *);

token_type_t
token_get_type(
        struct token *token);
const char *
token_get_value(
        struct token *token);
int
token_set_value(
        struct token *token,
        const char *value);
int
token_setn_value(
        struct token *token,
        const char *value,
        size_t len);

static inline void
token_list_dump(
        FILE *file,
        struct token_list *list)
{
    struct token *token = token_list_begin(list);
    while(token) {
        const char *type = token_type_to_string(token_get_type(token));
        const char *value = token_get_value(token);
        fprintf(file, "%s: \"%s\"\n",
                type,
                value);
        token = token_list_next(list, token);
    }
}

#endif
