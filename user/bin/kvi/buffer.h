#ifndef __KANAWHA__KVI_BUFFER_H__
#define __KANAWHA__KVI_BUFFER_H__

#include <stddef.h>

struct buffer;

int buffer_init(void);
int buffer_deinit(void);

struct buffer *
add_buffer(void);
int
drop_buffer(struct buffer *buf);

struct buffer *
add_buffer_with_path(
        const char *path);

int
buffer_set_path(
        struct buffer *buffer,
        const char *path);

size_t buffer_get_cursor_line(struct buffer *buffer);
int buffer_set_cursor_line(struct buffer *buffer, size_t line_no);

size_t buffer_get_cursor_char(struct buffer *buffer);
int buffer_set_cursor_char(struct buffer *buffer, size_t char_pos);

char
buffer_get_display_char(
        struct buffer *buffer,
        size_t line_no,
        size_t char_pos);

#endif
