
#include <kanawha/mmap.h>
#include <kanawha/sys-wrappers.h>
#include <kfb/kfb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <windd/windd.h>

int
main(int argc, const char **argv)
{
    int res;

    res = windd_client_init();
    if(res)
    {
        fprintf(stderr, "Failed to initialize windd library!\n");
        return -1;
    }

    struct window *window = NULL;
    window = windd_client_open();

    if(window != NULL)
    {
        printf("Opened client window!\n");
    }
    else
    {
        printf("Failed to create client window!\n");
    }

    //    void *buffer;
    //    res = kanawha_sys_mmap(
    //            window->conn,
    //            0,
    //            &buffer,
    //            0x1000,
    //            MMAP_SHARED|MMAP_PROT_WRITE|MMAP_PROT_READ);
    //    if(res) {
    //        fprintf(stderr, "Failed to map first page of connection
    //        buffer!\n"); return -1;
    //    }
    //
    //    strcpy((char*)buffer, "Hello World!");

    // printf("starting ping!\n");
    res = windd_window_ping(window);
    if(res)
    {
        fprintf(stderr, "windd_window_ping returned %d!\n", res);
        return res;
    }
    // printf("received pong!\n");

    struct gfx_layout layout;
    windd_window_get_layout(window, &layout);
    windd_window_reload_buffer(window);

    for(size_t i = 0; i < 100; i++)
    {
#define NUM_COLORS 11
        static const uint32_t colors[NUM_COLORS] = {
            0xFFFFFFFF,
            0xFF0000FF,
            0xFF0080FF,
            0xFF00FFFF,
            0xFF00FF80,
            0xFF00FF00,
            0xFF80FF00,
            0xFFFF8000,
            0xFFFF0000,
            0xFFFF0080,
            0xFF8000FF,
        };
        uint32_t color = colors[i % NUM_COLORS];

        windd_window_lock_buffer(window);
        if(window->buffer_size > 0)
        {
            struct kfb_image img = {
                .data = (void *)&color,
                .stride = 4,
                .offset = 0,
                .order = GFX_ORDER_ROW_MAJOR,
                .resx = 1,
                .resy = 1,
                .format = GFX_FORMAT_RGBA32,
            };
            kfb_blit_image(window->buffer,
                           window->layout.width,
                           window->layout.height,
                           0,
                           0,
                           &window->layout,
                           &img);
        }
        windd_window_unlock_buffer(window);

        usleep(100000);
    }

    windd_client_close(window);
    return 0;
}
