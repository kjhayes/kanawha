
#include <lens/lens.h>
#include <lens/window.h>
#include <lens/gfx.h>
#include <kfb/kfb.h>
#include <kanawha/gfx.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <threads.h>

static size_t CURRENT_COLOR = 0;

#define NUM_COLORS (sizeof(COLORS) / sizeof(COLORS[0]))

int
render_to_window(
        struct lens_window *window)
{
    int res;

    int layers_drawn = 0;

    lens_window_lock_gfx(window);

    struct lens_gfx_info *info = lens_window_get_gfx_info(window);
    if(info == NULL) {
        fprintf(stderr, "lterm: render_to_window failed to get lens_gfx_info!\n");
        lens_window_unlock_gfx(window);
        return 0;
    }

    void *frame = lens_window_get_gfx_frame(window);

    if(info->num_layers == 0) {
        //fprintf(stderr, "lterm: lens_gfx_info->num_layers == 0!\n");
    }

    // Actually draw to the frame
    for(int i = 0; i < info->num_layers; i++) {
        struct gfx_layout *layer = &info->layer_layout[i];
        struct gfx_layout color_layout = {
            .width = 1,
            .height = 1,
            .order = GFX_ORDER_ROW_MAJOR,
            .format = GFX_FORMAT_RGBA32,
            .offset = 0,
            .stride = 4,
        };
        uint32_t color = CURRENT_COLOR | 0xFF000000;
        kfb_blit(
                frame,
                layer->width,
                layer->height,
                0, 0,
                layer,
                &color,
                1, 1,
                0, 0,
                &color_layout);
        layers_drawn++;
    }

    lens_window_unlock_gfx(window);

    if(layers_drawn > 0) {
        lens_window_flush(window);
    }

    return 0;
}

int main(int argc, const char **argv)
{
    int res;
    res = lens_init();
    if(res) {
        fprintf(stderr, "lterm: failed to initialize liblens! err=%d\n",
                res);
        exit(EXIT_FAILURE);
    }

    struct lens_window *window;
    window = lens_open_window();
    if(window == NULL) {
        fprintf(stderr, "lterm: failed to open window! err=%d\n",
                res);
        lens_deinit();
        exit(EXIT_FAILURE);
    }

    int running = 1;
    while(running) {
        res = lens_window_poll(window);
        if(res) {
            running = 0;
            break;
        }

        struct input_event evt;
        res = lens_window_get_input(window, &evt);
        if(res > 0) {
            printf("lterm: Received input event!\n");
            CURRENT_COLOR += 0xABCDEF;
        }

        render_to_window(window);
    }

    lens_close_window(window);
    lens_deinit();
    return 0;
}

