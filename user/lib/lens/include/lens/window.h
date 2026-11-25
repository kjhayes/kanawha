#ifndef __KANAWHA__LENS_WINDOW_H__
#define __KANAWHA__LENS_WINDOW_H__

#include <kanawha/input.h>

struct lens_window;

struct lens_window *
lens_open_window(void);
int
lens_close_window(
        struct lens_window *window);

#endif
