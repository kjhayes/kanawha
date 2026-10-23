#include <lens/lens.h>
#include <lens/server.h>
#include <stdio.h>
#include <unistd.h>
#include "lensd.h"

int lensd_running = 1;

#define INFO(FMT, ...)\
    printf(FMT, ##__VA_ARGS__)

int main(int argc, const char **argv)
{
    int res;

    INFO("lensd: running...\n"); fflush(stdout);

    lensd_running = 1;
    lens_init(); 
    INFO("lensd: lens inited\n"); fflush(stdout);
    ctx_init();
    INFO("lensd: ctx inited\n"); fflush(stdout);
    display_init();
    INFO("lensd: display inited\n"); fflush(stdout);
    render_init();
    INFO("lensd: render inited\n"); fflush(stdout);
    listener_init();
    INFO("lensd: listener inited\n"); fflush(stdout);
    input_init();
    INFO("lensd: input inited\n"); fflush(stdout);

    add_display("/dev/fb/vga", 0);
    // add_display("/dev/fb/virtio-gpu-0", 0);

    add_input("/dev/input/ps2-kbd-0");
    add_input("/dev/input/ps2-mouse-0");
    // add_input("/dev/input/virtio-input-0");

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

