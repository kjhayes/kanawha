
#include <windd/windd.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <threads.h>
#include <string.h>
#include <sys/mman.h>
#include <kfb/kfb.h>
#include <kanawha/gfx.h>

static int window_main(void *window);

static void
usage(FILE *out) {
    fprintf(out, "windd [FRAMEBUFFER]\n");
}

int
main(int argc, const char **argv)
{
    int res;

    if(argc < 2) {
        usage(stderr);
        return -1;
    }

    const char *fb_path = argv[1];
    printf("windd: using framebuffer \"%s\"\n", fb_path);

    res = windd_server_init();
    if(res) {
        fprintf(stderr, "windd: Failed to initialize server!\n");
        return res;
    }

//    struct kfb_framebuffer *fb = kfb_open_framebuffer(fb_path);
//    if(fb == NULL) {
//        fprintf(stderr, "Failed to open framebuffer \"%s\"\n", fb_path);
//        return -1;
//    }
//
//    uint8_t color[4];
//    color[0] = 0xFF;
//    color[1] = 0xFF;
//    color[2] = 0x00;
//    color[3] = 0xFF;
//    struct kfb_image image;
//    image.data = color;
//    image.format = GFX_FORMAT_RGBA32;
//    image.resx = 1;
//    image.resy = 1;
//    image.order = GFX_ORDER_ROW_MAJOR;
//    image.stride = 4;
//    image.offset = 0;
//    image.data_size = 4;
//
//    kfb_blit_image_onto_layer(
//            fb,
//            0,
//            &image,
//            0, 0,
//            20, 20);
//    kfb_flush_framebuffer(fb);

    int running = 1;
    while(running)
    {
        res = waitpid(-1, NULL, WNOHANG);
        if(res < 0 && res != -EWOULDBLOCK)
        {
            fprintf(stderr, "windd: Failed to wait for children!\n");
        }

//        printf("windd: waiting for connection...\n");
        struct window *win = windd_server_await_connection();
        if(win == NULL) {
            continue;
        }

        thrd_t child;
        res = thrd_create(&child, window_main, win);
        if(res) {
            fprintf(stderr, "windd: Failed to create child thread for window!\n");
            windd_server_close_connection(win);
            continue;
        }
//        printf("windd: finished creating window thread...\n");
    }

    windd_server_deinit();

    return 0;
}

static int
window_main(void *_win)
{
    int res;
    struct window *win = _win;

    printf("windd: opened window thread...\n");

    void *buffer;
    res = kanawha_sys_mmap(
            win->conn,
            0,
            &buffer,
            0x1000,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        fprintf(stderr, "Failed to map window connection buffer!\n");
        windd_server_close_connection(win);
        return -1;
    }

    while(1)
    {
        printf("windd: window buffer \"%s\"\n", (char*)buffer);
        if(windd_window_disconnected(win)) {
            break;
        }
    }

    printf("windd: closing window thread...\n");
    windd_server_close_connection(win);

    return 0;
}

