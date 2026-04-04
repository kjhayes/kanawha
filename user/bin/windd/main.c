
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

struct window_ctx {
    struct window *window;
    struct window_ctx *next;
};

struct input_ctx {
    int lock;
    long mouse_x;
    long mouse_y;
    float mouse_x_sens;
    float mouse_y_sens;
};
static struct input_ctx input = {};


static unsigned long window_lock = 0;
static struct window_ctx *window_list = NULL;
static inline int
window_lock_acquire(void) {
    while(__atomic_fetch_or(&window_lock, 1, __ATOMIC_SEQ_CST))
    {
        thrd_yield();
    }
}
static inline int
window_lock_release(void) {
    window_lock = 0;
    __atomic_fetch_and(&window_lock, 0, __ATOMIC_SEQ_CST);
}

static struct window_ctx *
attach_window_ctx(struct window *win)
{
    struct window_ctx *ctx = malloc(sizeof(struct window_ctx));
    ctx->window = win;

    window_lock_acquire();
    if(window_list == NULL) {
        window_list = ctx;
    } else {
        struct window_ctx *last = window_list;
        while(last->next) {
            last = last->next;
        }
        ctx->next = NULL;
        last->next = ctx;
    }
    window_lock_release();

    return ctx;
}

static int
destroy_window_ctx(struct window_ctx *ctx)
{
    // Remove this window from the list
    window_lock_acquire();
    if(window_list == ctx) {
        window_list = ctx->next;
        ctx->next = NULL;
    } else {
        struct window_ctx *pred = NULL;
        pred = window_list;
        while(pred && pred->next != ctx) {
            pred = pred->next;
        }
        if(pred == NULL || pred->next != ctx) {
            window_lock_release();
            fprintf(stderr, "window_list is corrupted!\n");
            return -EINVAL;
        }
        pred->next = ctx->next;
        ctx->next = NULL;
    }
    window_lock_release();

    // ctx is no longer in the global list
    windd_server_close_connection(ctx->window);
    free(ctx);
    return 0;
}

struct render_ctx {
    struct kfb_framebuffer *fb;
    struct fb_mode_info *minfo;
};

static struct render_ctx render = {
    .fb = NULL,
};

static int
render_init(const char *path, int mode) 
{

    printf("windd: using framebuffer \"%s\"\n", path);
    render.fb = kfb_open_framebuffer(path);
    if(render.fb == NULL) {
        fprintf(stderr, "windd: failed to open framebuffer \"%s\"\n", path);
        return -1;
    }

    if(mode >= 0) {
        kfb_set_current_mode(render.fb, mode);
    }
    render.minfo = kfb_load_mode_info(render.fb, kfb_get_current_mode(render.fb));
    return 0;
}

static inline int
render_square(uint32_t color,
              unsigned int width,
              unsigned int height,
              unsigned int offset_x,
              unsigned int offset_y)
{
    int res;

    uint32_t _color = color;

    struct gfx_layout sqr_layout = {
        .offset = 0,
        .width = 1,
        .height = 1,
        .stride = 4,
        .order = GFX_ORDER_ROW_MAJOR,
        .format = GFX_FORMAT_RGBA32,
    };

    if(!render.fb->have_buffer_data) {
        return -EINVAL;
    }

    for(size_t li = 0; li < render.minfo->layer_count; li++) {
        struct fb_layer_info *linfo = &render.minfo->layer_infos[li];
        res = kfb_blit(
                render.fb->buffer_data,
                width,
                height,
                offset_x,
                offset_y,
                &linfo->layout,
                &_color,
                1, 1,
                0, 0,
                &sqr_layout);
    }

    return res;
}

static inline int
render_fill_all(uint32_t color)
{
    int res;
    struct fb_layer_info *linfo = &render.minfo->layer_infos[0];
    res = render_square(color,linfo->layout.width,linfo->layout.height,0,0);
    return res;
}

static inline int
render_flush(void)
{
    kfb_flush_framebuffer(render.fb);
}

static int
render_main(void *_n)
{
    srand(time(NULL));
    (void)_n;

    int running = 1;
    while(running) {
        // Draw the background
        union {
            uint32_t raw;
            struct {
                uint8_t r;
                uint8_t g;
                uint8_t b;
                uint8_t a;
            };
        } bg_color = {
            .r = 0x40,
            .g = 0x40,
            .b = 0x80,
            .a = 0xFF,
        };
        render_fill_all(bg_color.raw);

        // Draw all windows
        window_lock_acquire();
        struct window_ctx *wc = window_list;
        while(wc) {
            struct window *win = wc->window;
            if(win->position_valid && win->layout_valid) {
                if(render.fb->have_buffer_data && render.minfo != NULL) {
                    windd_window_reload_buffer(win);
                    windd_window_lock_buffer(win);
                    for(size_t li = 0; li < render.minfo->layer_count; li++) {
                        struct fb_layer_info *linfo = &render.minfo->layer_infos[li];
                        kfb_blit(
                            render.fb->buffer_data,
                            win->layout.width,
                            win->layout.height,
                            win->position.x,
                            win->position.y,
                            &linfo->layout,
                            win->buffer,
                            win->layout.width,
                            win->layout.height,
                            0, 0,
                            &win->layout);
                    }
                    //printf("rendering window at %d,%d of size %d,%d, first_byte=0x%x\n",
                    //        (int)win->position.x,
                    //        (int)win->position.y,
                    //        (int)win->layout.width,
                    //        (int)win->layout.height,
                    //        (unsigned int)*(uint8_t*)win->buffer
                    //      );
                    //render_square(0xFFFF00FF,
                    //              win->layout.width,
                    //              win->layout.height,
                    //              win->position.x,
                    //              win->position.y);
                    windd_window_unlock_buffer(win);
                }
            } 
            wc = wc->next;
        }

        // Draw the mouse
        unsigned long mouse_width = render.minfo->layer_infos[0].layout.width / 50;
        unsigned long mouse_height = render.minfo->layer_infos[0].layout.height / 50;
        if(mouse_width < 1) {
            mouse_width = 1;
        }
        if(mouse_height < 1) {
            mouse_height = 1;
        }
        
        render_square(0xFFFFFFFF,
                      mouse_width,
                      mouse_height,
                      input.mouse_x,
                      input.mouse_y);

        window_lock_release();

        // Flush the context
        render_flush();

        usleep(20000);
    }
}

static int
input_init(void)
{
    int res;
    input.lock = 0;
    input.mouse_x = 0;
    input.mouse_y = 0;
    input.mouse_x_sens = 0.5;
    input.mouse_y_sens = -0.5;
    return 0;
}

static int
input_lock_acquire(void) {
    while(__atomic_fetch_or(&input.lock, 1, __ATOMIC_SEQ_CST)) {}
}

static int
input_lock_release(void) {
    __atomic_fetch_and(&input.lock, 0, __ATOMIC_SEQ_CST);
}

static int shift_pressed = 0;

static int
handle_input_event(
        struct input_event *evt)
{
    int res;

    input_lock_acquire();
    window_lock_acquire();
    struct window_ctx *active_window = window_list;
    while(active_window && active_window->next) {
        active_window = active_window->next;
    }
    if(active_window == NULL) {
        fprintf(stderr, "windd: no active windows, losing input event!\n");
        input_lock_release();
        window_lock_release();
        return 0;
    }

    int eat_input = 0;

    if(evt->type == INPUT_EVT_KEY) {
        if(evt->key == INPUT_KEY_LSHIFT) {
            switch(evt->motion) {
                case INPUT_MOTION_PRESSED:
                case INPUT_MOTION_HELD:
                    shift_pressed = 1;
                    break;
                case INPUT_MOTION_RELEASED:
                    shift_pressed = 0;
                    break;
            }
        }
        else if(evt->key == INPUT_KEY_TAB) {
            if(evt->motion == INPUT_MOTION_PRESSED) {
                struct window_ctx *first = window_list;
                if(first != NULL) {
                    struct window_ctx *last = first;
                    struct window_ctx *second_to_last = NULL;
                    while(last->next) {
                        second_to_last = last;
                        last = last->next;
                    }
                    if(first != last) {
                        second_to_last->next = NULL;
                        last->next = first;
                        window_list = last;
                    }
                }
            }
            eat_input = 1;
        }
    }
    if(evt->type == INPUT_EVT_MOUSE) {
        long width = render.minfo->layer_infos[0].layout.width;
        long height = render.minfo->layer_infos[0].layout.height;

        long mouse_delta_x = evt->mouse_delta_x * input.mouse_x_sens;
        long mouse_delta_y = evt->mouse_delta_y * input.mouse_y_sens;
        input.mouse_x += mouse_delta_x;
        if(input.mouse_x < 0) {
            input.mouse_x = 0;
        }
        if(input.mouse_x >= width) {
            input.mouse_x = width-1;
        }

        input.mouse_y += mouse_delta_y;
        if(input.mouse_y < 0) {
            input.mouse_y = 0;
        }
        if(input.mouse_y >= height) {
            input.mouse_y = height - 1;
        }
        //printf("mouse_delta(%ld,%ld) mouse(%ld,%ld)\n",
        //        (long)mouse_delta_x,
        //        (long)mouse_delta_y,
        //        (long)input.mouse_x,
        //        (long)input.mouse_y
        //        );
    }

    if(!eat_input) {
        res = windd_window_send_input(active_window->window, evt);
        if(res) {
            fprintf(stderr, "windd: failed to send input event to active window!\n");
            input_lock_release();
            window_lock_release();
            return 0;
        }
    }

    input_lock_release();
    window_lock_release();
    return 0;
}

static int
input_main(void *_path) {
    int res;

    const char *path = _path;
    int file;
    res = kanawha_sys_open(path, FILE_PERM_READ, FILE_MODE_CLOSE_ON_EXEC, &file);
    if(res) {
        fprintf(stderr, "windd: failed to open input file: %s\n", path);
        return -1;
    }

    int running = 1;
    while(running) {
        struct input_event evt;
        ssize_t amt_read = read(file, &evt, sizeof(evt));
        if(amt_read == 0) {
            running = 0;
            break;
        }
        if(amt_read == sizeof(evt)) {
            res = handle_input_event(&evt);
            if(res) {
                running = 0;
                break;
            }
        }
    }
}

static int window_main(void *window);

static void
usage(FILE *out) {
    fprintf(out, "windd [FRAMEBUFFER] [FB-MODE] [INPUT-DEV(S) ...]\n");
}

int
main(int argc, const char **argv)
{
    int res;

    if(argc < 4) {
        usage(stderr);
        return -1;
    }

    int mode = -1;
    const char *mode_str = argv[2];
    mode = strtol(mode_str, NULL, 0);

    res = render_init(argv[1], mode);
    if(res) {
        fprintf(stderr, "windd: failed to setup render context!\n");
        return res;
    }

    res = input_init();
    if(res) {
        fprintf(stderr, "windd: failed to setup input context!\n");
    }

    res = windd_server_init();
    if(res) {
        fprintf(stderr, "windd: failed to initialize server!\n");
        return res;
    }

    // Launch all of the input threads...
    for(int i = 3; i < argc; i++) {
        thrd_t input_thread;
        res = thrd_create(&input_thread, input_main, (void*)argv[i]);
        if(res) {
            fprintf(stderr, "windd: failed to launch the input thread!\n");
            windd_server_deinit();
            return res;
        }
    }

    thrd_t render_thread;
    res = thrd_create(&render_thread, render_main, NULL);
    if(res) {
        fprintf(stderr, "windd: failed to launch the render thread!\n");
        windd_server_deinit();
        return res;
    }

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
    struct window_ctx *ctx;
    printf("windd: opened window thread...\n");

    {
        struct window *win = _win;
        ctx = attach_window_ctx(win);
        if(ctx == NULL) {
            windd_server_close_connection(win);
            return -EINVAL;
        }
    }

    {
        struct gfx_layout *backing = &render.minfo->layer_infos[0].layout;

        if(backing->width < 1 || backing->height < 1) {
            destroy_window_ctx(ctx);
            return -EINVAL;
        }

        struct gfx_layout layout = {
            .order = backing->order,
            .width = backing->width/2,
            .height = backing->height/2,
            .format = backing->format,
            .stride = backing->stride,
            .offset = 0,
        };
        windd_window_server_set_layout(ctx->window, &layout); 
        struct window_position position = {
            .x = rand() % (backing->width/2),
            .y = rand() % (backing->height/2),
        };
        windd_window_server_set_position(ctx->window, &position);
    }

    while(1)
    {
        printf("windd: poll...\n");
        windd_window_poll(ctx->window);
        printf("windd: poll DONE\n");
        if(windd_window_disconnected(ctx->window)) {
            break;
        }
    }

    printf("windd: closing window thread...\n");
    destroy_window_ctx(ctx);
    return 0;
}

