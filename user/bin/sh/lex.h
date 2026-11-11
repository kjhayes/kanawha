#ifndef __KANAWHA__SH_LEX_H__
#define __KANAWHA__SH_LEX_H__

#include <stdint.h>
#include <stddef.h>
#include "token.h"

int
lex_cmd(
        const char *cmdbuf,
        size_t buflen,
        struct token_list *list);

#endif
