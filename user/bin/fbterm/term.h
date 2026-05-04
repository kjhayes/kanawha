#ifndef __CABIN_FBTERM__TERM_H__
#define __CABIN_FBTERM__TERM_H__

#include "color.h"
#include <kanawha/gfx.h>
#include <stddef.h>
#include <stdio.h>

extern struct terminal_data
{
    // Display Data
    size_t width;
    size_t height;
    unsigned char *redraw_buffer;
    char *character_buffer;
    color_t *fg_color_buffer;
    color_t *bg_color_buffer;

    // State Data
    volatile int running;

    // Logging
    FILE *log_file;

    // Draw Data
    size_t cursor_x;
    size_t cursor_y;
    color_t cur_fg_color;
    color_t cur_bg_color;
    size_t tabsize;
    size_t last_character;

    unsigned raw : 1;
    unsigned echo_on : 1;
    unsigned cursor_visible : 1;
    unsigned bold_on : 1;
    unsigned italic_on : 1;
    unsigned underline_on : 1;

    struct palette *palette;

    int response_fd;

} terminal_data;

#define LOG(tdata, fmt, ...)                                                   \
    do                                                                         \
    {                                                                          \
        if(tdata->log_file != NULL)                                            \
        {                                                                      \
            fprintf(tdata->log_file, fmt, ##__VA_ARGS__);                      \
            fflush(tdata->log_file);                                           \
        }                                                                      \
    } while(0)

// "input" must outlive this terminal
int
init_terminal(FILE *log_file, size_t width, size_t height);

void
deinit_terminal(void);

int
terminal_resize(struct terminal_data *tdata, size_t width, size_t height);

void
terminal_mark_redraw(struct terminal_data *tdata, size_t __x, size_t __y);
void
terminal_mark_redraw_line(struct terminal_data *tdata, size_t __y);
void
terminal_mark_redraw_all(struct terminal_data *tdata);

void
terminal_newline(struct terminal_data *tdata);

void
terminal_advance_cursor(struct terminal_data *tdata);

void
terminal_set_cursor(struct terminal_data *data, int x, int y);

char
terminal_get_char_under_cursor(struct terminal_data *data);

void
terminal_move_cursor_up(struct terminal_data *data, int amount);

void
terminal_move_cursor_down(struct terminal_data *data, int amount);

void
terminal_move_cursor_right(struct terminal_data *data, int amount);

void
terminal_move_cursor_left(struct terminal_data *data, int amount);

void
terminal_move_cursor_to_column(struct terminal_data *data, int offset);

void
terminal_move_cursor_to_row(struct terminal_data *data, int offset);

void
terminal_put_at_cursor(struct terminal_data *tdata, char __c);

void
terminal_insert_at_cursor(struct terminal_data *tdata, char __c);
void
terminal_delete_at_cursor(struct terminal_data *tdata, char __fill_end);

void
terminal_delete_line_at_cursor(struct terminal_data *tdata, char __fill_end);

void
terminal_clear_cursor_to_end_of_screen(struct terminal_data *tdata);

void
terminal_clear_cursor_to_beginning_of_screen(struct terminal_data *tdata);

void
terminal_clear_entire_screen(struct terminal_data *tdata);

void
terminal_clear_cursor_to_end_of_line(struct terminal_data *tdata);

void
terminal_clear_start_of_line_to_cursor(struct terminal_data *tdata);

void
terminal_clear_cursor_line(struct terminal_data *tdata);

void
terminal_clear_line(struct terminal_data *tdata, size_t __y);

char
terminal_getc(struct terminal_data *tdata);

// Send data back to the shell
ssize_t
terminal_respond(
        struct terminal_data *tdata,
        void *response,
        size_t response_len);

#endif
