#ifndef __FB_TERM__ANSI_H__
#define __FB_TERM__ANSI_H__

#include "palette.h"
#include "term.h"

int ansi_terminal_init(struct terminal_data *tdata);
int ansi_terminal_update(struct terminal_data *tdata);

extern struct palette ansi256;

#endif
