#include <lens/lens.h>
#include <lens/server.h>
#include <stdio.h>
#include <unistd.h>
#include "lensd.h"

int lensd_running = 1;

int main(int argc, const char **argv)
{
    int res;

    lensd_running = 1;
    lens_init(); 
    ctx_init();
    display_init();
    render_init();
    listener_init();
    input_init();

    add_display("/dev/fb/vga", 2);

    add_input("/dev/input/ps2-kbd-0");
    add_input("/dev/input/ps2-mouse-0");

    while(lensd_running) {
        ctx_loop_iter();
        render_loop_iter();
        input_loop_iter();
        usleep(10000);
    }

    input_deinit();
    listener_deinit();
    render_deinit();
    display_deinit();
    ctx_deinit();
    lens_deinit();

    return 0;
}

