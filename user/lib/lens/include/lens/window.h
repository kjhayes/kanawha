#ifndef __KANAWHA__LENS_WINDOW_H__
#define __KANAWHA__LENS_WINDOW_H__

#include <kanawha/input.h>

struct lens_window;

struct lens_window *
lens_open_window(void);
int
lens_close_window(
        struct lens_window *window);

int
lens_window_poll(
        struct lens_window *window);

int
lens_window_flush(
        struct lens_window *window);

// 0 -> no event
// 1 -> *evt is now valid
// <0 -> errno
int
lens_window_get_input(
        struct lens_window *window,
        struct input_event *evt);

int
lens_window_lock_gfx(
        struct lens_window *window);
int
lens_window_unlock_gfx(
        struct lens_window *window);
struct lens_gfx_info *
lens_window_get_gfx_info(
        struct lens_window *window);
void*
lens_window_get_gfx_frame(
        struct lens_window *window);

#endif
