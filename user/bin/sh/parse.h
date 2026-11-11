#ifndef __KANAWHA__SH_PARSE_H__
#define __KANAWHA__SH_PARSE_H__

#include <stdint.h>
#include <stddef.h>
#include "token.h"
#include "cmd.h"

struct cmd *
parse_cmd(
        struct token_list *tokens);

#endif
