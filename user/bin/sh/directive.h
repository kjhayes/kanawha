#ifndef __CABIN_SH__DIRECTIVE_H__
#define __CABIN_SH__DIRECTIVE_H__

#include "command.h"

int
is_directive(
        struct simple_cmd *cmd);

// Consumes cmd even on failure
int
run_directive(
        struct simple_cmd *cmd);

#endif
