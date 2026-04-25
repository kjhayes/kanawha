
#include "input.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

struct input_ctx
{
    enum
    {
        INPUT_CTX_TYPE_FILE,
        INPUT_CTX_TYPE_WINDD,
        INPUT_CTX_TYPE_LENS,
    } type;

    union
    {
        struct
        {
            FILE *file;
        } file;
        struct
        {
            struct window *win;
        } windd;
        struct
        {
            struct lens_window *window;
        } lens;
    };
    unsigned shift_pressed : 1;
    unsigned ctrl_pressed : 1;
};

struct input_ctx *
create_file_input_ctx(FILE *file)
{
    struct input_ctx *ctx = malloc(sizeof(*ctx));
    if(ctx == NULL)
    {
        return NULL;
    }
    ctx->type = INPUT_CTX_TYPE_FILE;
    ctx->file.file = file;
    return ctx;
}

struct input_ctx *
create_windd_input_ctx(struct window *win)
{
    struct input_ctx *ctx = malloc(sizeof(*ctx));
    if(ctx == NULL)
    {
        return NULL;
    }
    ctx->type = INPUT_CTX_TYPE_WINDD;
    ctx->windd.win = win;
    ctx->shift_pressed = 0;
    ctx->ctrl_pressed = 0;
    return ctx;
}

struct input_ctx *
create_lens_input_ctx(struct lens_window *win)
{
    struct input_ctx *ctx = malloc(sizeof(*ctx));
    if(ctx == NULL)
    {
        return NULL;
    }
    ctx->type = INPUT_CTX_TYPE_LENS;
    ctx->lens.window = win;
    ctx->shift_pressed = 0;
    ctx->ctrl_pressed = 0;
    return ctx;
}

int
destroy_input_ctx(struct input_ctx *ctx)
{
    switch(ctx->type)
    {
    case INPUT_CTX_TYPE_FILE:
        break;
    default:
        return -EINVAL;
    }
    free(ctx);
    return 0;
}

static int
handle_input_event(struct input_ctx *ctx,
                   struct input_event *evt,
                   char *c_out)
{
    if(evt->type != INPUT_EVT_KEY)
    {
        return -EAGAIN;
    }

    input_key_t key = evt->key;
    input_motion_t motion = evt->motion;

    if(motion == INPUT_MOTION_RELEASED)
    {
        switch(key)
        {
        case INPUT_KEY_LSHIFT:
            ctx->shift_pressed = 0;
            break;
        case INPUT_KEY_LCTRL:
            ctx->ctrl_pressed = 0;
            break;
        default:
            break;
        }
    }
    else
    {

        int no_char = 0;
        char c;
        switch(key)
        {
        case INPUT_KEY_LCTRL:
            ctx->ctrl_pressed = 1;
            return -EAGAIN;
        case INPUT_KEY_LSHIFT:
            ctx->shift_pressed = 1;
            return -EAGAIN;
        case INPUT_KEY_MOUSE_LEFT:
        case INPUT_KEY_MOUSE_RIGHT:
        case INPUT_KEY_MOUSE_MIDDLE:
            return -EAGAIN;
        default:
            break;
        }

        if(ctx->ctrl_pressed)
        {
            switch(key)
            {
            case INPUT_KEY_A:
                c = 0x01;
                break; // ^A Start of Heading
            case INPUT_KEY_B:
                c = 0x02;
                break; // ^B Start of Text
            case INPUT_KEY_C:
                c = 0x03;
                break; // ^C End of Text
            case INPUT_KEY_D:
                c = 0x04;
                break; // ^D End of Transmission
            case INPUT_KEY_E:
                c = 0x05;
                break;
            case INPUT_KEY_F:
                c = 0x06;
                break;
            case INPUT_KEY_G:
                c = 0x07;
                break; // Bel
            case INPUT_KEY_H:
                c = 0x08;
                break; // Backspace
            case INPUT_KEY_I:
                c = 0x09;
                break; // Tab
            case INPUT_KEY_J:
                c = 0x0A;
                break; // LF
            case INPUT_KEY_K:
                c = 0x0B;
                break; // VT
            case INPUT_KEY_L:
                c = 0x0C;
                break; // FF
            case INPUT_KEY_M:
                c = 0x0D;
                break; // CR
            case INPUT_KEY_N:
                c = 0x0E;
                break; // Shift Out
            case INPUT_KEY_O:
                c = 0x0F;
                break; // Shift In
            case INPUT_KEY_P:
                c = 0x10;
                break;
            case INPUT_KEY_Q:
                c = 0x11;
                break;
            case INPUT_KEY_R:
                c = 0x12;
                break;
            case INPUT_KEY_S:
                c = 0x13;
                break;
            case INPUT_KEY_T:
                c = 0x14;
                break;
            case INPUT_KEY_U:
                c = 0x15;
                break;
            case INPUT_KEY_V:
                c = 0x16;
                break;
            case INPUT_KEY_W:
                c = 0x17;
                break;
            case INPUT_KEY_X:
                c = 0x18;
                break;
            case INPUT_KEY_Y:
                c = 0x19;
                break;
            case INPUT_KEY_Z:
                c = 0x1A;
                break;
            case INPUT_KEY_OPEN_SQR:
                c = 0x1B;
                break; // ESC
            case INPUT_KEY_BSLASH:
                c = 0x1C;
                break; // File Sep.
            default:
                no_char = 1;
                break;
            }
        }
        else
        {
            switch(key)
            {
            case INPUT_KEY_A:
                c = ctx->shift_pressed ? 'A' : 'a';
                break;
            case INPUT_KEY_B:
                c = ctx->shift_pressed ? 'B' : 'b';
                break;
            case INPUT_KEY_C:
                c = ctx->shift_pressed ? 'C' : 'c';
                break;
            case INPUT_KEY_D:
                c = ctx->shift_pressed ? 'D' : 'd';
                break;
            case INPUT_KEY_E:
                c = ctx->shift_pressed ? 'E' : 'e';
                break;
            case INPUT_KEY_F:
                c = ctx->shift_pressed ? 'F' : 'f';
                break;
            case INPUT_KEY_G:
                c = ctx->shift_pressed ? 'G' : 'g';
                break;
            case INPUT_KEY_H:
                c = ctx->shift_pressed ? 'H' : 'h';
                break;
            case INPUT_KEY_I:
                c = ctx->shift_pressed ? 'I' : 'i';
                break;
            case INPUT_KEY_J:
                c = ctx->shift_pressed ? 'J' : 'j';
                break;
            case INPUT_KEY_K:
                c = ctx->shift_pressed ? 'K' : 'k';
                break;
            case INPUT_KEY_L:
                c = ctx->shift_pressed ? 'L' : 'l';
                break;
            case INPUT_KEY_M:
                c = ctx->shift_pressed ? 'M' : 'm';
                break;
            case INPUT_KEY_N:
                c = ctx->shift_pressed ? 'N' : 'n';
                break;
            case INPUT_KEY_O:
                c = ctx->shift_pressed ? 'O' : 'o';
                break;
            case INPUT_KEY_P:
                c = ctx->shift_pressed ? 'P' : 'p';
                break;
            case INPUT_KEY_Q:
                c = ctx->shift_pressed ? 'Q' : 'q';
                break;
            case INPUT_KEY_R:
                c = ctx->shift_pressed ? 'R' : 'r';
                break;
            case INPUT_KEY_S:
                c = ctx->shift_pressed ? 'S' : 's';
                break;
            case INPUT_KEY_T:
                c = ctx->shift_pressed ? 'T' : 't';
                break;
            case INPUT_KEY_U:
                c = ctx->shift_pressed ? 'U' : 'u';
                break;
            case INPUT_KEY_V:
                c = ctx->shift_pressed ? 'V' : 'v';
                break;
            case INPUT_KEY_W:
                c = ctx->shift_pressed ? 'W' : 'w';
                break;
            case INPUT_KEY_X:
                c = ctx->shift_pressed ? 'X' : 'x';
                break;
            case INPUT_KEY_Y:
                c = ctx->shift_pressed ? 'Y' : 'y';
                break;
            case INPUT_KEY_Z:
                c = ctx->shift_pressed ? 'Z' : 'z';
                break;
            case INPUT_KEY_1:
                c = ctx->shift_pressed ? '!' : '1';
                break;
            case INPUT_KEY_2:
                c = ctx->shift_pressed ? '@' : '2';
                break;
            case INPUT_KEY_3:
                c = ctx->shift_pressed ? '#' : '3';
                break;
            case INPUT_KEY_4:
                c = ctx->shift_pressed ? '$' : '4';
                break;
            case INPUT_KEY_5:
                c = ctx->shift_pressed ? '%' : '5';
                break;
            case INPUT_KEY_6:
                c = ctx->shift_pressed ? '^' : '6';
                break;
            case INPUT_KEY_7:
                c = ctx->shift_pressed ? '&' : '7';
                break;
            case INPUT_KEY_8:
                c = ctx->shift_pressed ? '*' : '8';
                break;
            case INPUT_KEY_9:
                c = ctx->shift_pressed ? '(' : '9';
                break;
            case INPUT_KEY_0:
                c = ctx->shift_pressed ? ')' : '0';
                break;
            case INPUT_KEY_MINUS:
                c = ctx->shift_pressed ? '_' : '-';
                break;
            case INPUT_KEY_EQUAL_SIGN:
                c = ctx->shift_pressed ? '+' : '=';
                break;
            case INPUT_KEY_BACKTICK:
                c = ctx->shift_pressed ? '~' : '`';
                break;
            case INPUT_KEY_COMMA:
                c = ctx->shift_pressed ? '<' : ',';
                break;
            case INPUT_KEY_PERIOD:
                c = ctx->shift_pressed ? '>' : '.';
                break;
            case INPUT_KEY_FSLASH:
                c = ctx->shift_pressed ? '?' : '/';
                break;
            case INPUT_KEY_SEMICOLON:
                c = ctx->shift_pressed ? ':' : ';';
                break;
            case INPUT_KEY_SINGLE_QUOT:
                c = ctx->shift_pressed ? '"' : '\'';
                break;
            case INPUT_KEY_OPEN_SQR:
                c = ctx->shift_pressed ? '{' : '[';
                break;
            case INPUT_KEY_CLOSE_SQR:
                c = ctx->shift_pressed ? '}' : ']';
                break;
            case INPUT_KEY_BSLASH:
                c = ctx->shift_pressed ? '|' : '\\';
                break;
            case INPUT_KEY_SPACE:
                c = ' ';
                break;
            case INPUT_KEY_TAB:
                c = '\t';
                break;
            case INPUT_KEY_ENTER:
                c = '\n';
                break;
            case INPUT_KEY_BACKSPACE:
                c = '\b';
                break;
            case INPUT_KEY_ESCAPE:
                c = 033;
                break;
            default:
                no_char = 1;
                break;
            }
        }

        if(no_char)
        {
            printf("Unrecognized keycode '%d'\n", (int)evt->key);
            c = '?';
        }
        *c_out = c;
        return 0;
    }
    return -EAGAIN;
}

char
input_getc(struct input_ctx *ctx)
{
    switch(ctx->type)
    {
    case INPUT_CTX_TYPE_FILE:
        return fgetc(ctx->file.file);
    case INPUT_CTX_TYPE_WINDD:
    {
        int res;
        struct input_event evt;

        while(!windd_window_disconnected(ctx->windd.win))
        {
            res = windd_window_recv_input(ctx->windd.win, &evt);
            if(res == 0)
            {
                char c;
                res = handle_input_event(ctx, &evt, &c);
                if(res == 0)
                {
                    return c;
                }
                else
                {
                    // continue looping...
                    // This was probably a control
                    // key press or mouse motion
                }
            }
            else
            {
                if(res == -ENXIO)
                {
                    windd_window_poll(ctx->windd.win);
                }
                else
                {
                    return res;
                }
            }
        }
    }
    case INPUT_CTX_TYPE_LENS:
    {
        int res;
        char c;
        struct input_event evt;
        do {
            lens_window_poll(ctx->lens.window);
            int popped = lens_window_get_input(
                    ctx->lens.window,
                    &evt);
            if(popped <= 0) {
                continue;
            }
            res = handle_input_event(ctx, &evt, &c);
            if(res == 0) {
                return c;
            } else {
                continue;
            }
        } while(1);
    }
    default:
        return 0;
    }
}

int
input_poll(struct input_ctx *ctx)
{
    int res;
    switch(ctx->type)
    {
    case INPUT_CTX_TYPE_FILE:
    {
        struct pollfd pollfd[1];
        pollfd[0].fd = fileno(ctx->file.file);
        pollfd[0].events = POLLIN | POLLPRI;
        res = poll(pollfd, 1, 0);
        return (res > 0 && (pollfd[0].revents & (POLLIN | POLLPRI)));
    }
    break;
    case INPUT_CTX_TYPE_WINDD:
        return 0; // TODO add some polling mechanism to windd
    default:
        return 0;
    }
}
