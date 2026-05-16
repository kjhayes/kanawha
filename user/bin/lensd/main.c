#include <lens/lens.h>
#include <lens/server.h>
#include <stdio.h>
#include <unistd.h>
#include "lensd.h"

int lensd_running = 1;

int main(int argc, const char **argv)
{
    int res;

    printf("lensd: running...\n"); fflush(stdout);

    lensd_running = 1;
    lens_init(); 
    printf("lensd: lens inited\n"); fflush(stdout);
    ctx_init();
    printf("lensd: ctx inited\n"); fflush(stdout);
    display_init();
    printf("lensd: display inited\n"); fflush(stdout);
    render_init();
    printf("lensd: render inited\n"); fflush(stdout);
    listener_init();
    printf("lensd: listener inited\n"); fflush(stdout);
    input_init();
    printf("lensd: input inited\n"); fflush(stdout);

    // add_display("/dev/fb/vga", 2);
    add_display("/dev/fb/virtio-gpu-0", 0);

    // add_input("/dev/input/ps2-kbd-0");
    // add_input("/dev/input/ps2-mouse-0");
    add_input("/dev/input/virtio-input-0");

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

