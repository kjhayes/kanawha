
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

#define EVENT_QUEUE_LENGTH (64)

struct window_ctx {
    struct window *window;
    struct window_ctx *next;

    unsigned closed : 1;

    int evt_queue_lock;
    unsigned long evt_queue_len;
    unsigned long evt_queue_head;
    unsigned long evt_queue_tail;
    struct input_event *evt_queue;
};

static int
window_ctx_lock_evt_queue(
        struct window_ctx *ctx)
{
    while(__atomic_fetch_or(&ctx->evt_queue_lock, 1, __ATOMIC_SEQ_CST)) {}
}

static int
window_ctx_unlock_evt_queue(
        struct window_ctx *ctx)
{
    __atomic_fetch_and(&ctx->evt_queue_lock, 0, __ATOMIC_SEQ_CST);
}

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

    ctx->closed = 0;
    ctx->evt_queue_lock = 0;
    ctx->evt_queue_len = EVENT_QUEUE_LENGTH;
    ctx->evt_queue_head = 0;
    ctx->evt_queue_tail = 0;
    ctx->evt_queue = malloc(sizeof(struct input_event) * ctx->evt_queue_len);
    if(ctx->evt_queue == NULL) {
        free(ctx);
        return NULL;
    }

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
    free(ctx->evt_queue);
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

static inline unsigned long
compute_topbar_height(void) {
    unsigned long height = render.minfo->layer_infos[0].layout.height / 30;
    if(height < 1) {
        height = 1;
    }
    return height;
}

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

        unsigned long topbar_height = compute_topbar_height();
        if(topbar_height <= 0) {
            topbar_height = 1;
        }

        union {
            uint32_t raw;
            struct {
                uint8_t r;
                uint8_t g;
                uint8_t b;
                uint8_t a;
            };
        } topbar_color = {
            .r = 0x20,
            .g = 0x50,
            .b = 0x60,
            .a = 0xFF,
        };

        union {
            uint32_t raw;
            struct {
                uint8_t r;
                uint8_t g;
                uint8_t b;
                uint8_t a;
            };
        } close_color = {
            .r = 0x80,
            .g = 0x30,
            .b = 0x40,
            .a = 0xFF,
        };

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
                        render_square(
                                topbar_color.raw,
                                win->layout.width,
                                topbar_height,
                                win->position.x,
                                win->position.y - topbar_height);
                        render_square(
                                close_color.raw,
                                topbar_height < win->layout.width ? topbar_height : win->layout.width,
                                topbar_height,
                                win->position.x,
                                win->position.y - topbar_height);
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
    input.mouse_x_sens = 0.2;
    input.mouse_y_sens = -0.2;
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
        // fprintf(stderr, "windd: no active windows, losing input event!\n");
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

    if(evt->type == INPUT_EVT_KEY &&
      (evt->key == INPUT_KEY_MOUSE_LEFT || evt->key == INPUT_KEY_MOUSE_RIGHT))
    {
        int over_topbar = 0;
        int over_close_button;
        struct window_ctx *mouse_pred = NULL;
        struct window_ctx *mouse_window = NULL;
        {
            struct window_ctx *iter_pred = NULL;
            struct window_ctx *iter = window_list;
            for(struct window_ctx *iter = window_list; iter != NULL; iter_pred = iter, iter = iter->next) {
                // Check if the mouse in in this window's region
                if(!(iter->window->position_valid && iter->window->layout_valid)) {
                    continue;
                }

                unsigned long left = iter->window->position.x;
                unsigned long right = left + iter->window->layout.width;

                if(input.mouse_x < left || input.mouse_x >= right) {
                    // Does not intersect in the X-axis
                    continue;
                }

                unsigned long topbar_height = compute_topbar_height();
                unsigned long top = iter->window->position.y - topbar_height;
                unsigned long bottom = iter->window->position.y + iter->window->layout.height;
                if(input.mouse_y < top || input.mouse_y >= bottom) {
                    // Does not intersect in the Y-axis
                    continue;
                }

                mouse_pred = iter_pred;
                mouse_window = iter;
                if(input.mouse_y < iter->window->position.y) {
                    // We are hovering over the topbar
                    over_topbar = 1;
                    if(input.mouse_x < left + topbar_height) {
                        // We are hovering over the close botton
                        over_close_button = 1;
                    } else {
                        over_close_button = 0;
                    }
                } else {
                    over_topbar = 0;
                    over_close_button = 0;
                }
            }
        }

        if(mouse_window) {
            //printf("windd: mouse event on window! (close=%d,topbar=%d)\n",
            //        (int)(over_close_button),
            //        (int)(over_topbar && !over_close_button)
            //        );
            if(over_close_button && evt->key == INPUT_KEY_MOUSE_LEFT && evt->motion == INPUT_MOTION_PRESSED) {
                printf("marking window as closed!\n");
                mouse_window->closed = 1;
                eat_input = 1;
            }
            else if(mouse_window->next) {
                // We want to focus the mouse window
                // Remove it from the list
                if(window_list == mouse_window) {
                    window_list = mouse_window->next;
                } else {
                    mouse_pred->next = mouse_window->next;
                }
                mouse_window->next = NULL;

                // Add it to the end of the list
                struct window_ctx *iter = window_list;
                while(iter && iter->next) {
                    iter = iter->next;
                }
                if(iter != NULL) {
                    iter->next = mouse_window;
                } else {
                    window_list = mouse_window;
                }

                eat_input = 1;
            }
        } 
    }

    if(!eat_input) {
        window_ctx_lock_evt_queue(active_window);
        // Enqueue the event
        if(((active_window->evt_queue_head+1)%active_window->evt_queue_len) == active_window->evt_queue_tail) {
            // The queue is full, drop the last event
            active_window->evt_queue_tail = (active_window->evt_queue_tail+1)%active_window->evt_queue_len;
        }
        active_window->evt_queue[active_window->evt_queue_head] = *evt;
        active_window->evt_queue_head = (active_window->evt_queue_head+1) % active_window->evt_queue_len;
        window_ctx_unlock_evt_queue(active_window);
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
window_input_main(void *_ctx) {
    int res;
    struct window_ctx *ctx = _ctx;
    
    int running = 1;

    // TODO This thread should be able to block waiting for input
    // for the window... This is busy polling at the moment
    // If the window stops reading input the close button may not work
    // as well...
    while(running && !ctx->closed) {
        int received_evt = 0;
        struct input_event evt;

        while(!received_evt) {
            window_ctx_lock_evt_queue(ctx);
            if(ctx->evt_queue_tail != ctx->evt_queue_head) {
                evt = ctx->evt_queue[ctx->evt_queue_tail];
                ctx->evt_queue_tail = (ctx->evt_queue_tail + 1) % ctx->evt_queue_len;
                received_evt = 1;
            }
            window_ctx_unlock_evt_queue(ctx);

            if(!received_evt) {
                usleep(10000); // Sleep for a 10 milliseconds
            }
        }

        res = windd_window_send_input(ctx->window, &evt);
        if(res) {
            fprintf(stderr, "windd: failed to send input event to active window!\n");
        }
    }

    return 0;
}

static int
window_poll_main(void *_ctx)
{
    struct window_ctx *ctx = _ctx;

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

    while(1)
    {
        printf("windd: poll...\n");
        windd_window_poll(ctx->window);
        printf("windd: poll DONE\n");
        if(windd_window_disconnected(ctx->window)) {
            return 0;
        }
    }
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

    thrd_t input_thrd;
    res = thrd_create(&input_thrd, window_input_main, ctx);
    if(res) {
        fprintf(stderr, "windd: failed to create window input thread!\n");
        destroy_window_ctx(ctx);
        return res;
    }

    thrd_t poll_thrd;
    res = thrd_create(&poll_thrd, window_poll_main, ctx);
    if(res) {
        fprintf(stderr, "windd: failed to create window input thread!\n");
        destroy_window_ctx(ctx);
        return res;
    }

    while(waitpid(-1, NULL, WNOHANG) == 0 && !ctx->closed) {
        // BUSY WAITING... Sad...
        sleep(1); // This doesn't need to be fast (sleep for a whole second)
    }

    printf("windd: window_main, killing children...\n");
    kill(input_thrd.pid, SIGQUIT);
    kill(poll_thrd.pid, SIGQUIT);

    printf("windd: window_main, waiting for children...\n");
    waitpid(input_thrd.pid, NULL, 0);
    waitpid(poll_thrd.pid, NULL, 0);

    printf("windd: closing window thread...\n");
    destroy_window_ctx(ctx);
    return 0;
}

