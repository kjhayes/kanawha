
#include "frame.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

struct frame {
    unsigned int width;
    unsigned int height;

    char *char_buf;
    char *redisplay_buf;
    char *rerender_buf;
};

static struct frame *
alloc_frame(void) {
    struct frame *f = malloc(sizeof(*f));
    f->width = 0;
    f->height = 0;
    f->char_buf = NULL;
    f->redisplay_buf = NULL;
    f->rerender_buf = NULL;
    return f;
}
static int
free_frame(struct frame *f)
{
    free(f->char_buf);
    free(f->redisplay_buf);
    free(f->rerender_buf);
    free(f);
    return 0;
}

static struct frame *root_frame = NULL;

int frame_init(void)
{
    root_frame = alloc_frame();
    if(root_frame == NULL) {
        return -ENOMEM;
    }
    return 0;
}
int frame_deinit(void)
{
    free_frame(root_frame);
    return 0;
}

void frame_lock(struct frame *frame)
{
    return;
}
void frame_unlock(struct frame *frame)
{
    return;
}

struct frame *
frame_get_root(void)
{
    return root_frame;
}

int
frame_resize(
        struct frame *frame,
        unsigned int w,
        unsigned int h
        )
{
    frame->width = w;
    frame->height = h;
    size_t num_cells = w*h;
    free(frame->char_buf);
    free(frame->redisplay_buf);
    free(frame->rerender_buf);
    frame->char_buf = NULL;
    frame->redisplay_buf = NULL;
    frame->rerender_buf = NULL;
    if(num_cells > 0) {
        frame->char_buf = malloc(sizeof(frame->char_buf[0])*num_cells);
        frame->redisplay_buf = malloc(sizeof(frame->redisplay_buf[0])*num_cells);
        frame->rerender_buf = malloc(sizeof(frame->rerender_buf[0])*num_cells);
        if((frame->char_buf == NULL)
         ||(frame->redisplay_buf == NULL)
         ||(frame->rerender_buf == NULL)
         )
        {
            free(frame->char_buf);
            free(frame->redisplay_buf);
            free(frame->rerender_buf);
            frame->width = 0;
            frame->height = 0;
            return -ENOMEM;
        }
        _Static_assert(sizeof(frame->char_buf[0]) == 1, "");
        memset(frame->char_buf, ' ', sizeof(frame->char_buf[0])*num_cells);
        _Static_assert(sizeof(frame->redisplay_buf[0]) == 1, "");
        memset(frame->redisplay_buf, 1, sizeof(frame->redisplay_buf[0])*num_cells);
        _Static_assert(sizeof(frame->rerender_buf[0]) == 1, "");
        memset(frame->rerender_buf, 1, sizeof(frame->rerender_buf[0])*num_cells);
    }
    return 0;
}

ssize_t
frame_width(struct frame *frame)
{
    return frame->width;
}
ssize_t
frame_height(struct frame *frame)
{
    return frame->height;
}

int frame_redisplay_all(struct frame *frame)
{
    size_t num_cells = frame->width * frame->height;
    _Static_assert(sizeof(frame->redisplay_buf[0]) == 1, "");
    memset(frame->redisplay_buf, 1, num_cells);
    return 0;
}
int frame_rerender_all(struct frame *frame)
{
    size_t num_cells = frame->width * frame->height;
    _Static_assert(sizeof(frame->rerender_buf[0]) == 1, "");
    memset(frame->rerender_buf, 1, num_cells);
    return 0;
}

int
frame_redisplay_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return -EINVAL;
    }
    frame->redisplay_buf[x + (y*frame->width)] = 1;
    return 0;
}

int
frame_rerender_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return -EINVAL;
    }
    frame->rerender_buf[x + (y*frame->width)] = 1;
    return 0;
}

int
frame_mark_cell_displayed(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return -EINVAL;
    }
    frame->redisplay_buf[x + (y*frame->width)] = 0;
    return 0;
}

int
frame_mark_cell_rendered(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return -EINVAL;
    }
    frame->rerender_buf[x + (y*frame->width)] = 0;
    return 0;
}

int
frame_should_redisplay_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return 0;
    }
    return frame->redisplay_buf[x + (y*frame->width)];
}

int
frame_should_rerender_cell(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return 0;
    }
    return frame->rerender_buf[x + (y*frame->width)];
}

int
frame_set_char(
        struct frame *frame,
        unsigned long x,
        unsigned long y,
        char c)
{
    if(x >= frame->width || y >= frame->height) {
        return -EINVAL;
    }
    frame->char_buf[x + (y*frame->width)] = c;
    frame->redisplay_buf[x + (y*frame->width)] = 1;
    return 0;
}

char
frame_get_char(
        struct frame *frame,
        unsigned long x,
        unsigned long y)
{
    if(x >= frame->width || y >= frame->height) {
        return ' ';
    }
    return frame->char_buf[x + (y*frame->width)];
}

