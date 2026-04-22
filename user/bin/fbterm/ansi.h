#ifndef __FB_TERM__ANSI_H__
#define __FB_TERM__ANSI_H__

#include "input.h"
#include "palette.h"
#include "term.h"

int
ansi_terminal_init(struct terminal_data *tdata);
int
ansi_terminal_update(struct terminal_data *tdata, struct input_ctx *idata);

extern struct palette ansi256;

#endif
