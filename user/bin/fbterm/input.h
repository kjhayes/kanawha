#ifndef __FBTERM_INPUT_H__
#define __FBTERM_INPUT_H__

#include <stdio.h>
#include <windd/windd.h>
#include <lens/window.h>

struct input_ctx;

struct input_ctx *
create_file_input_ctx(FILE *file);

struct input_ctx *
create_windd_input_ctx(struct window *win);

struct input_ctx *
create_lens_input_ctx(struct lens_window *win);


int
destroy_input_ctx(struct input_ctx *ctx);

char
input_getc(struct input_ctx *ctx);

// Returns 0 if no data can be read immediately
int
input_poll(struct input_ctx *ctx);

#endif
