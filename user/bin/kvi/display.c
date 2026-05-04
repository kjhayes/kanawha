
#include "display.h"
#include "frame.h"
#include <termios.h>
#include <stdio.h>
#include <ansiterm/ansiterm.h>

struct termios stdin_t;

static inline int
disable_cursor(void)
{
    printf("\033[?25l");
    fflush(stdout);
}

static inline int
enable_cursor(void)
{
    printf("\033[?25h");
    fflush(stdout);
}

int display_init(void)
{
    int res;

    res = tcgetattr(fileno(stdin), &stdin_t);
    if(res) {
        fprintf(stderr, "display_init: tcgetattr failed!\n");
        return res;

    }

    struct termios t = stdin_t;

    t.c_lflag &= ~(ICANON);
    t.c_lflag &= ~(ECHO);
    t.c_lflag &= ~(ECHOE);
    t.c_lflag &= ~(ECHOK);
    t.c_lflag &= ~(ECHONL);

    res = tcsetattr(fileno(stdin), TCSANOW, &t);
    if(res) {
        fprintf(stderr, "display_init: tcsetattr failed!\n");
        return res;
    }

    return 0;
}
int display_deinit(void)
{
    int res;
    res = tcsetattr(fileno(stdin), TCSANOW, &stdin_t);
    if(res) {
        fprintf(stderr, "display_deinit: tcsetattr failed!\n");
        return res;
    }
    return 0;
}

int display_flush(void)
{
    unsigned long width, height;
    ansiterm_get_dimensions(&width, &height);

    struct frame *frame;
    frame = frame_get_root();
    frame_lock(frame);
    ssize_t cur_width = frame_width(frame);
    ssize_t cur_height = frame_height(frame);
    if(cur_width != width || cur_height != height) {
        frame_resize(frame, width, height);
        frame_rerender_all(frame);
        frame_unlock(frame);
        printf("skipping display_flush() due to resize old=(%lu,%lu) new=(%lu,%lu)!\n",
                (unsigned long)cur_width,
                (unsigned long)cur_height,
                (unsigned long)width,
                (unsigned long)height);
        return 0;
    }

    unsigned long cursor_x,cursor_y;
    ansiterm_get_cursor(&cursor_x,&cursor_y);

    // Draw everything
    for(size_t y = 0; y < height; y++) {
    for(size_t x = 0; x < width; x++) {

        if(!frame_should_redisplay_cell(
                    frame,
                    x,y))
        {
            continue;
        }

        ansiterm_set_cursor(x,y);
        fputc(frame_get_char(frame,x,y), stdout);
        frame_mark_cell_displayed(frame, x, y);
    }}

    fflush(stdout);

    ansiterm_set_cursor(cursor_x,cursor_y);

    frame_unlock(frame);

    return 0;
}

