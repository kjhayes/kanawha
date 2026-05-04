#ifndef __KVI__INPUT_H__
#define __KVI__INPUT_H__

#include <stdio.h>

int input_init(void);
int input_deinit(void);

int
add_file_input_source(FILE *file);

// Get a character from the current
// input source.
// Blocking if none are available.
char input_getc(void);

#endif
