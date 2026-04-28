
#include "ansi.h"
#include "input.h"
#include "palette.h"
#include "term.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_FG_COLOR_INDEX 7
#define DEFAULT_BG_COLOR_INDEX 0

static void
handle_sgr(struct terminal_data *tdata, int *param, int num_param)
{
    for(size_t i = 0; i < num_param; i++)
    {
        int n = param[i];

        color_t temp_color;

        // LOG(tdata, "SGR=%d\n", n);

        switch(n)
        {
        case 0: // Reset
            tdata->cur_fg_color =
                palette_read_color(tdata->palette, DEFAULT_FG_COLOR_INDEX);
            tdata->cur_bg_color =
                palette_read_color(tdata->palette, DEFAULT_BG_COLOR_INDEX);
            tdata->bold_on = 0;
            tdata->italic_on = 0;
            tdata->underline_on = 0;
            continue;
        case 1: // Bold
            tdata->bold_on = 1;
            continue;
        case 3: // Italic
            tdata->italic_on = 1;
            continue;
        case 4: // Underline
            tdata->underline_on = 1;
            continue;
        case 7: // Invert
            temp_color = tdata->cur_fg_color;
            tdata->cur_fg_color = tdata->cur_bg_color;
            tdata->cur_bg_color = temp_color;
            continue;
        case 22: // Normal Intensity
            tdata->bold_on = 0;
            continue;
        case 23: // Not Italic
            tdata->italic_on = 0;
            continue;
        case 24: // Not Underline
            tdata->underline_on = 0;
            continue;

        case 39:
            tdata->cur_fg_color =
                palette_read_color(tdata->palette, DEFAULT_FG_COLOR_INDEX);
            continue;
        case 49:
            tdata->cur_bg_color =
                palette_read_color(tdata->palette, DEFAULT_BG_COLOR_INDEX);
            continue;
        }

        if(30 <= n && n <= 37)
        {
            int index = n - 30;
            tdata->cur_fg_color = palette_read_color(tdata->palette, index);
            continue;
        }

        if(40 <= n && n <= 47)
        {
            int index = n - 40;
            tdata->cur_bg_color = palette_read_color(tdata->palette, index);
            continue;
        }

        if(90 <= n && n <= 97)
        {
            int index = n - 90;
            tdata->cur_fg_color = palette_read_color(tdata->palette, 8 + index);
            continue;
        }
        if(100 <= n && n <= 107)
        {
            int index = n - 100;
            tdata->cur_bg_color = palette_read_color(tdata->palette, 8 + index);
            continue;
        }

        if(10 <= n && n <= 19)
        {
            int font_num = n - 10;
            if(font_num == 0)
            {
                // Do nothing
            }
            else
            {
                LOG(tdata, "Cannot load alternative font: %d\n", font_num);
            }
            continue;
        }

        if(n == 38)
        {
            if(i + 1 > num_param)
            {
                LOG(tdata, "SGR 38 without any additional parameters!\n");
                continue;
            }
            i++;
            int s = param[i];
            if(s == 5)
            {
                // 8-bit color
                if(i + 1 > num_param)
                {
                    i++;
                    int index = param[i];
                    tdata->cur_bg_color =
                        palette_read_color(tdata->palette, index);
                }
                else
                {
                    LOG(tdata,
                        "SGR 38;5; Too Few Arguments for "
                        "8-bit Color Depth!\n");
                }
            }
            else if(s == 2)
            {
                // 24-bit color
                if(i + 3 > num_param)
                {
                    int r = param[i + 1];
                    int g = param[i + 2];
                    int b = param[i + 3];
                    tdata->cur_fg_color.r = r;
                    tdata->cur_fg_color.g = g;
                    tdata->cur_fg_color.b = b;
                    tdata->cur_fg_color.a = 0xFF;
                    i += 3;
                }
                else
                {
                    LOG(tdata,
                        "SGR 38;2; Too Few Arguments for "
                        "24-bit Color Depth!\n");
                }
            }
            else
            {
                LOG(tdata, "SGR 38 Unknown Color Depth %d!\n", s);
            }
            continue;
        }
        if(n == 48)
        {
            if(i + 1 > num_param)
            {
                LOG(tdata, "SGR 48 without any additional parameters!\n");
                continue;
            }
            i++;
            int s = param[i];
            if(s == 5)
            {
                // 8-bit color
                if(i + 1 > num_param)
                {
                    i++;
                    int index = param[i];
                    tdata->cur_bg_color =
                        palette_read_color(tdata->palette, index);
                }
                else
                {
                    LOG(tdata,
                        "SGR 48;5; Too Few Arguments for "
                        "8-bit Color Depth!\n");
                }
            }
            else if(s == 2)
            {
                // 24-bit color
                if(i + 3 > num_param)
                {
                    int r = param[i + 1];
                    int g = param[i + 2];
                    int b = param[i + 3];
                    tdata->cur_bg_color.r = r;
                    tdata->cur_bg_color.g = g;
                    tdata->cur_bg_color.b = b;
                    tdata->cur_bg_color.a = 0xFF;
                    i += 3;
                }
                else
                {
                    LOG(tdata,
                        "SGR 48;2; Too Few Arguments for "
                        "24-bit Color Depth!\n");
                }
            }
            else
            {
                LOG(tdata, "SGR 48 Unknown Color Depth %d!\n", s);
            }
            continue;
        }

        LOG(tdata, "Unknown SGR Value: %d\n", n);
    }
}
static void
handle_dsr(struct terminal_data *tdata, int *param, int num_param)
{
    if(num_param == 1) {
        switch(param[0]) {
            case 6:
                { // Cursor Position
                    char resp_buf[32];
                    snprintf(resp_buf, 32, "\033[%lu;%luR",
                            (unsigned long)tdata->width,
                            (unsigned long)tdata->height);

                    resp_buf[32-1] = '\0';

                    size_t len = strlen(resp_buf);
                    LOG(tdata, "\n");

                    ssize_t written = terminal_respond(
                            tdata,
                            resp_buf,
                            len);

                    if(written != len) {
                        LOG(tdata, "DSR 6: Failed to write full response!\n");
                    }
                    return;
                }
                break;
            default:
                LOG(tdata, "DSR %d is unknown!\n", param[0]);
        }
    }
    LOG(tdata, "Unknown DSR request!\n");
    return;
}
static void
handle_csi(struct terminal_data *tdata, struct input_ctx *idata)
{
    char c;

    size_t num_parameter_bytes = 0;
    char parameter_bytes[16 + 1];
    c = input_getc(idata);
    while(num_parameter_bytes < 16)
    {
        if(0x30 <= c && c <= 0x3F)
        {
            parameter_bytes[num_parameter_bytes] = c;
            num_parameter_bytes++;
            c = input_getc(idata);
        }
        else
        {
            break;
        }
    }
    parameter_bytes[num_parameter_bytes] = '\0';

    size_t num_intermediate_bytes = 0;
    char intermediate_bytes[16 + 1];
    while(num_intermediate_bytes < 16)
    {
        if(0x20 <= c && c <= 0x2F)
        {
            intermediate_bytes[num_intermediate_bytes] = c;
            num_intermediate_bytes++;
            c = input_getc(idata);
        }
        else
        {
            break;
        }
    }
    intermediate_bytes[num_intermediate_bytes] = '\0';

    if(!(0x40 <= c && c <= 0x7E))
    {
        // Missing Terminator
        //LOG(tdata,
        //    "CSI Escape is Missing Terminator (last-char=0x%x,\'%c\')\n",
        //    (unsigned int)c, (char)c);
        //terminal_put_at_cursor(tdata, '?');
        //terminal_advance_cursor(tdata);
        return;
    }
    char terminator = c;

#define MAX_COMMON_PARAMS 32

    int is_common = 1;

    int num_common_params = 0;
    int common_params[MAX_COMMON_PARAMS] = {0};

    if(strspn(parameter_bytes, ";0123456789") == num_parameter_bytes)
    {
        const char *delim = ";";
        char *iter = strtok(parameter_bytes, delim);
        while(iter)
        {
            if(num_common_params >= MAX_COMMON_PARAMS)
            {
                LOG(tdata,
                    "Too many common paramters provided to CSI "
                    "escape "
                    "sequence!\n");
                break;
            }
            num_common_params++;
            if(strlen(iter) == 0)
            {
                common_params[num_common_params - 1] = 0;
            }
            else
            {
                common_params[num_common_params - 1] = atoi(iter);
            }
            iter = strtok(NULL, delim);
        }
        if(num_common_params == 0)
        {
            num_common_params = 1;
        }
    }
    else
    {
        is_common = 0;
    }

    if(0x70 <= terminator && terminator <= 0x7E)
    {
        is_common = 0;
    }

    if(!is_common)
    {
        num_common_params = 0;
        LOG(tdata,
            "Ignoring non-common CSI sequence: terminator=0x%x\n",
            terminator);
        return;
    }

    switch(terminator)
    {
    case 'J':
        // Erase in display
        switch(common_params[0])
        {
        case 0:
            terminal_clear_cursor_to_end_of_screen(tdata);
            break;
        case 1:
            terminal_clear_cursor_to_beginning_of_screen(tdata);
            break;
        case 2:
            terminal_clear_entire_screen(tdata);
            tdata->cursor_x = 0;
            tdata->cursor_y = 0;
            break;
        case 3:
            terminal_clear_entire_screen(
                tdata); /* Note we should also erase any "scrollback */
            break;
        default:
            LOG(tdata,
                "CSI n %c, invalid parameter n=%d\n",
                terminator,
                common_params[0]);
            terminal_put_at_cursor(tdata, '?');
            terminal_advance_cursor(tdata);
            break;
        }
        break;
    case 'K':
        // Erase in line
        switch(common_params[0])
        {
        case 0:
            terminal_clear_cursor_to_end_of_line(tdata);
            break;
        case 1:
            terminal_clear_start_of_line_to_cursor(tdata);
            break;
        case 2:
            terminal_clear_cursor_line(tdata);
            break;
        default:
            LOG(tdata,
                "CSI n %c, invalid parameter n=%d\n",
                terminator,
                common_params[0]);
            terminal_put_at_cursor(tdata, '?');
            terminal_advance_cursor(tdata);
            break;
        }
        break;
    case 'A':
        // Move Up n
        terminal_move_cursor_up(tdata, common_params[0]);
        break;
    case 'B':
        // Move Down n
        terminal_move_cursor_down(tdata, common_params[0]);
        break;
    case 'C':
        // Move Right n
        terminal_move_cursor_right(tdata, common_params[0]);
        break;
    case 'D':
        // Move Left n
        terminal_move_cursor_left(tdata, common_params[0]);
        break;
    case 'G':
        if(common_params[0] > 0)
        {
            common_params[0] -= 1;
        }
        terminal_move_cursor_to_column(tdata, common_params[0]);
        break;
    case 'd':
        if(common_params[0] > 0)
        {
            common_params[0] -= 1;
        }
        terminal_move_cursor_to_row(tdata, common_params[0]);
        break;
    case 'H':
    case 'f':
        // Move to (p-1, n-1) {default (1,1)}
        if(common_params[0] == 0)
        {
            common_params[0] = 1;
        }
        if(common_params[1] == 0)
        {
            common_params[1] = 1;
        }
        terminal_set_cursor(tdata, common_params[1] - 1, common_params[0] - 1);
        break;
    case 'S':
        // nel (act like \r\n)
        terminal_newline(tdata);
        terminal_move_cursor_to_column(tdata, 0);
        break;
    case 'm':
        handle_sgr(tdata, common_params, num_common_params);
        break;
    case 'n':
        handle_dsr(tdata, common_params, num_common_params);
        break;
    case 'b':
        // Repeat previous character n times
        for(size_t i = 0; i < common_params[0]; i++)
        {
            terminal_put_at_cursor(tdata, tdata->last_character);
            terminal_advance_cursor(tdata);
        }
        break;
    case '@':
        // Insert n blanks
        if(common_params[0] < 1)
        {
            common_params[0] = 1;
        }
        for(size_t i = 0; i < common_params[0]; i++)
        {
            terminal_insert_at_cursor(tdata, ' ');
        }
        break;
    case 'P':
        // Delete n characters
        if(common_params[0] < 1)
        {
            common_params[0] = 1;
        }
        for(size_t i = 0; i < common_params[0]; i++)
        {
            terminal_delete_at_cursor(tdata, ' ');
        }
        break;
    case 'M':
        // Delete n Lines
        if(common_params[0] < 1)
        {
            common_params[0] = 1;
        }
        for(size_t i = 0; i < common_params[0]; i++)
        {
            terminal_delete_line_at_cursor(tdata, ' ');
        }
        break;
    default:
        LOG(tdata,
            "Unknown CSI Terminator 0x%x, '%c'!\n",
            terminator,
            terminator);
        terminal_put_at_cursor(tdata, '?');
        terminal_advance_cursor(tdata);
        break;
    }
}

static inline void
handle_escape(struct terminal_data *tdata, struct input_ctx *idata)
{
    char c = input_getc(idata);

    switch(c)
    {
    case '[':
        return handle_csi(tdata, idata);

    // ^[(* and ^[)* Try to set the character set, ignore them.
    case '(':
    case ')':
        LOG(tdata, "Cannot handle alternative character sets!\n");
        input_getc(idata);
        break;
    // ^[=* and ^[>* Try to enter/exit alternate keypad modes, ignore them.
    case '=':
    case '>':
        LOG(tdata, "Cannot handle alternative character sets!\n");
        break;

    // Shift In/Out Tries to set the character set, ignore them.
    case 0xE:
    case 0xF:
        LOG(tdata, "Cannot handle shift/in shift/out!\n");
        break;

    default:
        LOG(tdata, "Unexpected Escape Character 0x%x\n", (unsigned int)c);
        terminal_put_at_cursor(tdata, '?');
        terminal_advance_cursor(tdata);
        break;
    }
}

int
ansi_terminal_init(struct terminal_data *tdata)
{
    tdata->palette = &ansi256;

    terminal_mark_redraw_all(tdata);

    return 0;
}

int
ansi_terminal_update(struct terminal_data *tdata, struct input_ctx *idata)
{
    char c = input_getc(idata);

    switch(c)
    {
    case '\r':
        tdata->cursor_x = 0;
        break;
    case '\n':
        tdata->cursor_x = 0;
        terminal_newline(tdata);
        break;
    case '\b':
        if(tdata->cursor_x > 0)
        {
            tdata->cursor_x--;
            terminal_mark_redraw(tdata, tdata->cursor_x + 1, tdata->cursor_y);
            terminal_mark_redraw(tdata, tdata->cursor_x, tdata->cursor_y);
        }
        break;
    case '\t':
        for(size_t i = 0; i < tdata->tabsize; i++)
        {
            terminal_put_at_cursor(tdata, ' ');
            terminal_advance_cursor(tdata);
            if(tdata->cursor_x % tdata->tabsize == 0)
            {
                break;
            }
        }
        break;
    case 07:
        // BEL (ignore)
        LOG(tdata, "Received BEL (ignoring...)\n");
        break;
    case 033:
        handle_escape(tdata, idata);
        break;
    default:
        if(isprint(c))
        {
            terminal_put_at_cursor(tdata, c);
            terminal_advance_cursor(tdata);
            tdata->last_character = c;
        }
        else
        {
            // LOG(tdata,
            //     "Unexpected un-printable character 0x%x\n",
            //     (unsigned int)c);
            terminal_put_at_cursor(tdata, '?');
            terminal_advance_cursor(tdata);
        }
        break;
    }

    return 0;
}

// Palettes

const static color_t COLOR_WHITE = {
    .r = 0xC0,
    .g = 0xC0,
    .b = 0xC0,
    .a = 0xFF,
};
const static color_t COLOR_BLACK = {
    .r = 0x00,
    .g = 0x00,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_RED = {
    .r = 0xC0,
    .g = 0x00,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_GREEN = {
    .r = 0x00,
    .g = 0xC0,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_BLUE = {
    .r = 0x00,
    .g = 0x00,
    .b = 0xC0,
    .a = 0xFF,
};
const static color_t COLOR_YELLOW = {
    .r = 0x80,
    .g = 0x80,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_MAGENTA = {
    .r = 0x80,
    .g = 0x00,
    .b = 0x80,
    .a = 0xFF,
};
const static color_t COLOR_CYAN = {
    .r = 0x00,
    .g = 0x80,
    .b = 0x80,
    .a = 0xFF,
};

const static color_t COLOR_BRIGHT_WHITE = {
    .r = 0xFF,
    .g = 0xFF,
    .b = 0xFF,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_BLACK = {
    .r = 0x60,
    .g = 0x60,
    .b = 0x60,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_RED = {
    .r = 0xFF,
    .g = 0x00,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_GREEN = {
    .r = 0x00,
    .g = 0xFF,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_BLUE = {
    .r = 0x00,
    .g = 0x00,
    .b = 0xFF,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_YELLOW = {
    .r = 0xFF,
    .g = 0xFF,
    .b = 0x00,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_MAGENTA = {
    .r = 0xFF,
    .g = 0x00,
    .b = 0xFF,
    .a = 0xFF,
};
const static color_t COLOR_BRIGHT_CYAN = {
    .r = 0x00,
    .g = 0xFF,
    .b = 0xFF,
    .a = 0xFF,
};

static color_t
__ansi_256_get_color(size_t index)
{
    if(index > 255)
    {
        return COLOR_BLACK;
    }

    color_t c;
    if(index < 16)
    {
        switch(index)
        {
        case 0:
            c = COLOR_BLACK;
            break;
        case 1:
            c = COLOR_RED;
            break;
        case 2:
            c = COLOR_GREEN;
            break;
        case 3:
            c = COLOR_YELLOW;
            break;
        case 4:
            c = COLOR_BLUE;
            break;
        case 5:
            c = COLOR_MAGENTA;
            break;
        case 6:
            c = COLOR_CYAN;
            break;
        case 7:
            c = COLOR_WHITE;
            break;
        case 8:
            c = COLOR_BRIGHT_BLACK;
            break;
        case 9:
            c = COLOR_BRIGHT_RED;
            break;
        case 10:
            c = COLOR_BRIGHT_GREEN;
            break;
        case 11:
            c = COLOR_BRIGHT_YELLOW;
            break;
        case 12:
            c = COLOR_BRIGHT_BLUE;
            break;
        case 13:
            c = COLOR_BRIGHT_MAGENTA;
            break;
        case 14:
            c = COLOR_BRIGHT_CYAN;
            break;
        case 15:
            c = COLOR_BRIGHT_WHITE;
            break;
        default:
            c = COLOR_BLACK;
            break; // Should never happen
        }
    }
    else if(index < 232)
    {
        // Extended Colors
        c.r = ((index - 16) / 36) * 51;
        c.g = (((index - 16) % 36) / 6) * 51;
        c.b = ((index - 16) % 6) * 51;
        c.a = 0xFF;
    }
    else
    { // index < 256
        size_t mult = index - 231;
        c.r = mult * 10;
        c.g = mult * 10;
        c.b = mult * 10;
        c.a = 0xFF;
    }
    return c;
}

struct palette ansi256 = {
    .num_colors = 256,
    .read_color = __ansi_256_get_color,
};
