#ifndef __KVI__FRAME_H__
#define __KVI__FRAME_H__

#include <unistd.h>

struct frame;

int frame_init(void);
int frame_deinit(void);

void frame_lock(struct frame *frame);
void frame_unlock(struct frame *frame);

struct frame *
frame_get_root(void);

int
frame_resize(
        struct frame *frame,
        unsigned int w,
        unsigned int h
        );

ssize_t frame_width(struct frame *frame);
ssize_t frame_height(struct frame *frame);

int frame_redisplay_all(struct frame *frame);
int frame_rerender_all(struct frame *frame);

int
frame_redisplay_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_rerender_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_mark_cell_displayed(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_mark_cell_rendered(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_rerender_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_should_redisplay_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_should_rerender_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

int
frame_set_char(
        struct frame *frame,
        unsigned long x,
        unsigned long y,
        char c);

char
frame_get_char(
        struct frame *frame,
        unsigned long x,
        unsigned long y);

#endif
