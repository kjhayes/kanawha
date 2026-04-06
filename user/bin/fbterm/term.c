
#include "term.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct terminal_data terminal_data = {0};

int
terminal_resize(struct terminal_data *tdata, size_t width, size_t height)
{
    if(tdata->width == width && tdata->height == height) {
        return 0;
    }

    free(tdata->redraw_buffer);
    free(tdata->character_buffer);
    free(tdata->fg_color_buffer);
    free(tdata->bg_color_buffer);

    tdata->width = width;
    tdata->height = height;

    tdata->redraw_buffer = malloc(width * height * sizeof(unsigned char));
    if(tdata->redraw_buffer == NULL)
    {
        return -EINVAL;
    }
    memset(tdata->redraw_buffer, 1, width * height * sizeof(unsigned char));

    tdata->character_buffer = malloc(width * height * sizeof(char));
    if(tdata->character_buffer == NULL)
    {
        free(tdata->redraw_buffer);
        return -EINVAL;
    }
    memset(tdata->character_buffer, ' ', width * height * sizeof(char));

    tdata->fg_color_buffer = malloc(width * height * sizeof(color_t));
    if(tdata->fg_color_buffer == NULL)
    {
        free(tdata->character_buffer);
        free(tdata->redraw_buffer);
        return -EINVAL;
    }
    tdata->bg_color_buffer = malloc(width * height * sizeof(color_t));
    if(tdata->bg_color_buffer == NULL)
    {
        free(tdata->fg_color_buffer);
        free(tdata->character_buffer);
        free(tdata->redraw_buffer);
        return -EINVAL;
    }

    for(size_t y = 0; y < height; y++)
    {
        for(size_t x = 0; x < width; x++)
        {
            tdata->fg_color_buffer[x + (y * width)].r = 0xFF;
            tdata->fg_color_buffer[x + (y * width)].g = 0xFF;
            tdata->fg_color_buffer[x + (y * width)].b = 0xFF;
            tdata->fg_color_buffer[x + (y * width)].a = 0xFF;

            tdata->bg_color_buffer[x + (y * width)].r = 0x00;
            tdata->bg_color_buffer[x + (y * width)].g = 0x00;
            tdata->bg_color_buffer[x + (y * width)].b = 0x00;
            tdata->bg_color_buffer[x + (y * width)].a = 0xFF;
        }
    }
    memset(tdata->bg_color_buffer, 0x00, width * height * sizeof(color_t));

    return 0;
}

int
init_terminal(FILE *log_file,
              size_t width,
              size_t height)
{
    struct terminal_data *tdata = &terminal_data;
    memset(tdata, 0, sizeof(struct terminal_data));

    tdata->log_file = log_file;

    tdata->redraw_buffer = NULL;
    tdata->character_buffer = NULL;
    tdata->fg_color_buffer = NULL;
    tdata->bg_color_buffer = NULL;

    terminal_resize(tdata, width, height);

    tdata->running = 1;
    tdata->cursor_x = 0;
    tdata->cursor_y = 0;
    tdata->cur_fg_color.r = 0xFF;
    tdata->cur_fg_color.g = 0xFF;
    tdata->cur_fg_color.b = 0xFF;
    tdata->cur_fg_color.a = 0xFF;
    tdata->cur_bg_color.r = 0x00;
    tdata->cur_bg_color.g = 0x00;
    tdata->cur_bg_color.b = 0x00;
    tdata->cur_bg_color.a = 0xFF;

    tdata->raw = 0;
    tdata->echo_on = 1;
    tdata->bold_on = 0;
    tdata->italic_on = 0;
    tdata->underline_on = 0;

    tdata->last_character = ' ';
    tdata->tabsize = 4;

    return 0;
}

void
deinit_terminal(void)
{
    struct terminal_data *tdata = &terminal_data;
    free(tdata->bg_color_buffer);
    free(tdata->fg_color_buffer);
    free(tdata->character_buffer);
    free(tdata->redraw_buffer);
}

void
terminal_mark_redraw(struct terminal_data *tdata, size_t __x, size_t __y)
{
    tdata->redraw_buffer[__x + (__y * tdata->width)] = 1;
}
void
terminal_mark_redraw_line(struct terminal_data *tdata, size_t __y)
{
    size_t offset = tdata->width * __y;
    memset(tdata->redraw_buffer + offset, 1, tdata->width);
}
void
terminal_mark_redraw_all(struct terminal_data *tdata)
{
    memset(tdata->redraw_buffer,
           1,
           tdata->width * tdata->height * sizeof(char));
}

void
terminal_newline(struct terminal_data *tdata)
{
    tdata->cursor_y++;
    if(tdata->cursor_y >= tdata->height)
    {
        memmove(tdata->character_buffer,
                tdata->character_buffer + tdata->width,
                tdata->width * (tdata->height - 1) * sizeof(char));
        memmove(tdata->fg_color_buffer,
                tdata->fg_color_buffer + tdata->width,
                tdata->width * (tdata->height - 1) * sizeof(color_t));
        memmove(tdata->bg_color_buffer,
                tdata->bg_color_buffer + tdata->width,
                tdata->width * (tdata->height - 1) * sizeof(color_t));
        for(size_t __i = 0; __i < tdata->width; __i++)
        {
            tdata
                ->character_buffer[__i + (tdata->width * (tdata->height - 1))] =
                ' ';
            tdata->fg_color_buffer[__i + (tdata->width * (tdata->height - 1))]
                .data = tdata->cur_fg_color.data;
            tdata->bg_color_buffer[__i + (tdata->width * (tdata->height - 1))]
                .data = tdata->cur_bg_color.data;
        }
        tdata->cursor_y = tdata->height - 1;
        terminal_mark_redraw_all(tdata);
    }
}

void
terminal_advance_cursor(struct terminal_data *tdata)
{
    tdata->cursor_x++;
    terminal_mark_redraw(tdata, tdata->cursor_x - 1, tdata->cursor_y);
    if(tdata->cursor_x >= tdata->width)
    {
        tdata->cursor_x = 0;
        terminal_newline(tdata);
    }
    terminal_mark_redraw(tdata, tdata->cursor_x, tdata->cursor_y);
}

void
terminal_set_cursor(struct terminal_data *data, int x, int y)
{
    int old_x = data->cursor_x;
    int old_y = data->cursor_y;

    if(x < 0)
    {
        x = 0;
    }
    else if(x >= data->width)
    {
        x = data->width - 1;
    }
    if(y < 0)
    {
        y = 0;
    }
    else if(y >= data->height)
    {
        y = data->height - 1;
    }

    data->cursor_x = x;
    data->cursor_y = y;

    terminal_mark_redraw(data, old_x, old_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

char
terminal_get_char_under_cursor(struct terminal_data *data)
{
    return data
        ->character_buffer[data->cursor_x + (data->cursor_y * data->width)];
}

void
terminal_move_cursor_up(struct terminal_data *data, int amount)
{
    int cur_y = data->cursor_y;
    int old_y = cur_y;
    cur_y -= amount;
    if(cur_y < 0)
    {
        cur_y = 0;
    }
    data->cursor_y = cur_y;
    terminal_mark_redraw(data, data->cursor_x, old_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_move_cursor_down(struct terminal_data *data, int amount)
{
    int cur_y = data->cursor_y;
    int old_y = cur_y;
    cur_y += amount;
    if(cur_y >= data->height)
    {
        cur_y = data->height - 1;
    }
    data->cursor_y = cur_y;
    terminal_mark_redraw(data, data->cursor_x, old_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_move_cursor_right(struct terminal_data *data, int amount)
{
    int cur_x = data->cursor_x;
    int old_x = cur_x;
    cur_x += amount;
    if(cur_x >= data->width)
    {
        cur_x = data->width - 1;
    }
    data->cursor_x = cur_x;
    terminal_mark_redraw(data, old_x, data->cursor_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_move_cursor_left(struct terminal_data *data, int amount)
{
    int cur_x = data->cursor_x;
    int old_x = cur_x;
    cur_x -= amount;
    if(cur_x < 0)
    {
        cur_x = 0;
    }
    data->cursor_x = cur_x;
    terminal_mark_redraw(data, old_x, data->cursor_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_move_cursor_to_column(struct terminal_data *data, int offset)
{
    int old_offset = data->cursor_x;
    if(offset >= data->width)
    {
        data->cursor_x = data->width - 1;
    }
    else
    {
        data->cursor_x = offset;
    }
    terminal_mark_redraw(data, old_offset, data->cursor_y);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_move_cursor_to_row(struct terminal_data *data, int offset)
{
    int old_offset = data->cursor_y;
    if(offset >= data->height)
    {
        data->cursor_y = data->height - 1;
    }
    else
    {
        data->cursor_y = offset;
    }
    terminal_mark_redraw(data, data->cursor_x, old_offset);
    terminal_mark_redraw(data, data->cursor_x, data->cursor_y);
}

void
terminal_put_at_cursor(struct terminal_data *tdata, char __c)
{
    tdata
        ->character_buffer[tdata->cursor_x + (tdata->cursor_y * tdata->width)] =
        __c;
    tdata->fg_color_buffer[tdata->cursor_x + (tdata->cursor_y * tdata->width)] =
        tdata->cur_fg_color;
    tdata->bg_color_buffer[tdata->cursor_x + (tdata->cursor_y * tdata->width)] =
        tdata->cur_bg_color;
    terminal_mark_redraw(tdata, tdata->cursor_x, tdata->cursor_y);
}

void
terminal_insert_at_cursor(struct terminal_data *tdata, char c)
{
    size_t size_of_rest_of_line = tdata->width - tdata->cursor_x;
    size_t offset = tdata->cursor_x + (tdata->cursor_y * tdata->width);
    if(size_of_rest_of_line > 1)
    {
        memmove(tdata->character_buffer + offset + 1,
                tdata->character_buffer + offset,
                size_of_rest_of_line - 1);
        memmove(tdata->fg_color_buffer + offset + 1,
                tdata->fg_color_buffer + offset,
                size_of_rest_of_line - 1);
        memmove(tdata->bg_color_buffer + offset + 1,
                tdata->bg_color_buffer + offset,
                size_of_rest_of_line - 1);
    }
    memset(tdata->redraw_buffer + offset, 1, size_of_rest_of_line);
    terminal_put_at_cursor(tdata, c);
}

void
terminal_delete_at_cursor(struct terminal_data *tdata, char __fill_end)
{
    size_t size_to_move = tdata->width - (tdata->cursor_x + 1);
    size_t offset = tdata->cursor_x + (tdata->cursor_y * tdata->width);
    memmove(tdata->character_buffer + offset,
            tdata->character_buffer + offset + 1,
            size_to_move);
    memmove(tdata->fg_color_buffer + offset,
            tdata->fg_color_buffer + offset + 1,
            size_to_move);
    memmove(tdata->bg_color_buffer + offset,
            tdata->bg_color_buffer + offset + 1,
            size_to_move);
    tdata->character_buffer[(tdata->width - 1) +
                            (tdata->width * tdata->cursor_y)] = __fill_end;
    terminal_mark_redraw_line(tdata, tdata->cursor_y);
}

void
terminal_delete_line_at_cursor(struct terminal_data *tdata, char __fill_end)
{
    if(tdata->cursor_y != tdata->width - 1)
    {
        size_t lines_after = (tdata->width - tdata->cursor_y) - 1;
        size_t amt_to_move = lines_after * tdata->width;
        size_t cursor_line_offset = tdata->width * tdata->cursor_y;
        size_t next_line_offset = tdata->width * (tdata->cursor_y + 1);
        memmove(tdata->character_buffer + cursor_line_offset,
                tdata->character_buffer + next_line_offset,
                amt_to_move);
        memmove(tdata->fg_color_buffer + cursor_line_offset,
                tdata->fg_color_buffer + next_line_offset,
                amt_to_move);
        memmove(tdata->bg_color_buffer + cursor_line_offset,
                tdata->bg_color_buffer + next_line_offset,
                amt_to_move);
    }
    // Clear the bottom line
    terminal_clear_line(tdata, tdata->width - 1);
    terminal_mark_redraw_all(tdata);
}

void
terminal_clear_cursor_to_end_of_screen(struct terminal_data *tdata)
{
    size_t cursor_offset = tdata->cursor_x + (tdata->cursor_y * tdata->width);
    size_t room_after = (tdata->width * tdata->height) - cursor_offset;
    memset(tdata->character_buffer + cursor_offset, ' ', room_after);
    for(size_t i = 0; i < room_after; i++)
    {
        tdata->fg_color_buffer[cursor_offset + i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[cursor_offset + i] = tdata->cur_bg_color;
    }
    memset(tdata->redraw_buffer + cursor_offset, 1, room_after);
}
void
terminal_clear_cursor_to_beginning_of_screen(struct terminal_data *tdata)
{
    size_t cursor_offset = tdata->cursor_x + (tdata->cursor_y * tdata->width);
    memset(tdata->character_buffer, ' ', cursor_offset + 1);
    for(size_t i = 0; i < cursor_offset + 1; i++)
    {
        tdata->fg_color_buffer[i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[i] = tdata->cur_bg_color;
    }
    memset(tdata->redraw_buffer, 1, cursor_offset + 1);
}
void
terminal_clear_entire_screen(struct terminal_data *tdata)
{
    memset(tdata->character_buffer, ' ', tdata->width * tdata->height);
    for(size_t i = 0; i < tdata->width * tdata->height; i++)
    {
        tdata->fg_color_buffer[i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[i] = tdata->cur_bg_color;
    }
    memset(tdata->redraw_buffer, 1, tdata->width * tdata->height);
}

void
terminal_clear_cursor_to_end_of_line(struct terminal_data *tdata)
{
    size_t cursor_offset = tdata->cursor_x + (tdata->cursor_y * tdata->width);
    size_t rest_of_line = tdata->width - tdata->cursor_x;
    memset(tdata->character_buffer + cursor_offset, ' ', rest_of_line);
    for(size_t i = 0; i < rest_of_line; i++)
    {
        tdata->fg_color_buffer[cursor_offset + i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[cursor_offset + i] = tdata->cur_bg_color;
    }
    memset(tdata->redraw_buffer + cursor_offset, 1, rest_of_line);
}

void
terminal_clear_start_of_line_to_cursor(struct terminal_data *tdata)
{
    size_t line_offset = (tdata->cursor_y * tdata->width);
    size_t len = tdata->cursor_x;
    memset(tdata->character_buffer + line_offset, ' ', len);
    for(size_t i = 0; i < len; i++)
    {
        tdata->fg_color_buffer[line_offset + i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[line_offset + i] = tdata->cur_bg_color;
    }
    terminal_mark_redraw_line(tdata, tdata->cursor_y);
}

void
terminal_clear_cursor_line(struct terminal_data *tdata)
{
    terminal_clear_line(tdata, tdata->cursor_y);
}

void
terminal_clear_line(struct terminal_data *tdata, size_t __y)
{
    size_t line_offset = (__y * tdata->width);
    memset(tdata->character_buffer + line_offset, ' ', tdata->width);
    for(size_t i = 0; i < tdata->width; i++)
    {
        tdata->fg_color_buffer[line_offset + i] = tdata->cur_fg_color;
        tdata->bg_color_buffer[line_offset + i] = tdata->cur_bg_color;
    }
    terminal_mark_redraw_line(tdata, __y);
}

