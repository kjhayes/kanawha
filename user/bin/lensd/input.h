#ifndef __LENSD__INPUT_H__
#define __LENSD__INPUT_H__

int input_init(void);
int input_deinit(void);
int input_loop_iter(void);
int add_input(const char *path);
int add_all_inputs(const char *path);

#endif
