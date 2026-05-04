
#include "buffer.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ilist.h>

static ilist_t buffer_list;

struct buffer_line {
    size_t buflen;
    size_t linelen;
    char *linebuf;
};

struct buffer
{
    char *path;

    size_t cursor_line_desired;
    size_t cursor_char_desired;

    size_t num_lines;
    size_t lines_buflen;
    struct buffer_line **lines_buf;
};

int buffer_init(void)
{
    ilist_init(&buffer_list);
    return 0;
}
int buffer_deinit(void)
{
    return 0;
}

struct buffer *
add_buffer(void)
{
    struct buffer *buffer = malloc(sizeof(*buffer));
    if(buffer == NULL) {
        return NULL;
    }

    buffer->path = NULL;
    buffer->cursor_line_desired = 0;
    buffer->cursor_char_desired = 0;

    buffer->num_lines = 0;
    buffer->lines_buflen = 256;
    buffer->lines_buf = malloc(sizeof(struct buffer_line*)*buffer->lines_buflen);
    if(buffer->lines_buf == NULL) {
        free(buffer);
        return NULL;
    }
    memset(buffer->lines_buf, 0, sizeof(struct buffer_line*)*buffer->lines_buflen);

    return buffer;
}

int
drop_buffer(struct buffer *buf)
{
    if(buf->path) {
        free(buf->path);
    }
    free(buf);
    return 0;
}

struct buffer *
add_buffer_with_path(const char *path)
{
    int res;
    struct buffer *buf = add_buffer();
    if(buf == NULL) {
        return NULL;
    }
    res = buffer_set_path(buf, path);
    if(res) {
        drop_buffer(buf);
        return NULL;
    }
    return buf;
}

int
buffer_set_path(
        struct buffer *buffer,
        const char *path)
{
    if(buffer->path != NULL) {
        char *old = buffer->path;
        buffer->path = NULL;
        free(old);
    }

    buffer->path = strdup(path);
    if(buffer->path == NULL) {
        return -ENOMEM;
    }

    return 0;
}

size_t buffer_get_cursor_line(struct buffer *buffer)
{
    if(buffer->cursor_line_desired >= buffer->num_lines) {
        if(buffer->num_lines == 0) {
            return 0;
        } else {
            return buffer->num_lines-1;
        }
    } else {
        return buffer->cursor_line_desired;
    }
}
int buffer_set_cursor_line(struct buffer *buffer, size_t line_no)
{
    buffer->cursor_line_desired = line_no;
    return 0;
}

size_t buffer_get_cursor_char(struct buffer *buffer)
{
    size_t line_no = buffer_get_cursor_line(buffer);
    struct buffer_line *line = buffer->lines_buf[line_no];
    if(line == NULL) {
        return 0;
    }
    if(buffer->cursor_line_desired >= line->linelen) {
        return line->linelen-1;
    } else {
        return buffer->cursor_line_desired;
    }
}
int buffer_set_cursor_char(struct buffer *buffer, size_t char_pos)
{
    buffer->cursor_char_desired = char_pos;
    return 0;
}

char
buffer_get_display_char(
        struct buffer *buffer,
        size_t line_no,
        size_t char_pos)
{
    if(line_no >= buffer->num_lines) {
        return '\0';
    }
    struct buffer_line *line = buffer->lines_buf[line_no];
    if(line == NULL || char_pos >= line->linelen) {
        return '\0';
    }
    return line->linebuf[char_pos];
}

