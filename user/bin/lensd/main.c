#include <lens/lens.h>
#include <lens/server.h>
#include <stdio.h>
#include <unistd.h>
#include <kanawha/syscall.h>
#include "lensd.h"

int lensd_running = 1;

#define INFO(FMT, ...)\
    printf(FMT, ##__VA_ARGS__)

static const char *fb_dev_path = "/dev/fb/";
static const char *input_dev_path = "/dev/input/";

static int
foreach_subdir(
        const char *dir_path,
        int(*callback)(const char *path))
{
    int res;
    fd_t dir;
    res = kanawha_sys_open(
                dir_path,
                FILE_PERM_READ,
                0,
                &dir);
    if(res) {
        return res;
    }

    res = kanawha_sys_dirbegin(dir);
    if(res == 0) {
#define BUFLEN 0x100
        char namebuf[BUFLEN];
        char pathbuf[BUFLEN];

        while(1) {
            res = kanawha_sys_dirname(dir, namebuf, BUFLEN);
            if(res) {
                kanawha_sys_close(dir);
                return res;
            }
            namebuf[BUFLEN-1] = '\0';

            snprintf(pathbuf, BUFLEN, "%s/%s", dir_path, namebuf);
            pathbuf[BUFLEN-1] = '\0';

            res = (*callback)(pathbuf);
            if(res) {
                kanawha_sys_close(dir);
                return res;
            }

            res = kanawha_sys_dirnext(dir);
            if(res) {
                break;
            }
        }
#undef BUFLEN
    }

    kanawha_sys_close(dir);
    return 0;
}

static int
add_display_callback(
        const char *path)
{
    printf("lensd: adding display: %s\n", path);
    add_display(path, 0);
    return 0;
}

static int
add_all_displays(void) {
    foreach_subdir(fb_dev_path, add_display_callback);
}

static int
add_input_callback(
        const char *path)
{
    printf("lensd: adding input: %s\n", path);
    add_input(path);
    return 0;
}

static int
add_all_inputs(void) {
    foreach_subdir(input_dev_path, add_input_callback);
}

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

    add_all_displays();
    add_all_inputs();
    // add_display("/dev/fb/vga", 0);
    // add_display("/dev/fb/virtio-gpu-0", 0);

    // add_input("/dev/input/ps2-kbd-0");
    // add_input("/dev/input/ps2-mouse-0");
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

