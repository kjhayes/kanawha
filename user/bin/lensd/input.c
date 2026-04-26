
#include "lensd.h"
#include <lens/input_buffer.h>
#include <kanawha/input.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ilist.h>
#include <string.h>
#include <stdlib.h>
#include <semaphore.h>

#define MAX_INPUT_EVENTS_PER_ITER (8)

static struct lens_input_buffer *input_buffer = NULL;

sem_t input_source_lock;
ilist_t input_source_list;

struct input_source
{
    char *path;
    thrd_t thread;

    unsigned shift_pressed : 1;
    unsigned ctrl_pressed : 1;

    ilist_node_t list_node;
};

#define KEY_RIGHT INPUT_KEY_L
#define KEY_LEFT INPUT_KEY_H
#define KEY_UP INPUT_KEY_K
#define KEY_DOWN INPUT_KEY_J

// Centralized function called by all input
// source's threads
static int
handle_input_event(
        struct input_source *src,
        struct input_event *evt)
{
    int eat_input = 0;
    if(evt->type == INPUT_EVT_KEY) {
        switch(evt->key) {
            case INPUT_KEY_LSHIFT:
                src->shift_pressed = evt->motion == INPUT_MOTION_RELEASED ? 0 : 1;
                break;
            case INPUT_KEY_LCTRL:
                src->ctrl_pressed = evt->motion == INPUT_MOTION_RELEASED ? 0 : 1;
                break;
            case INPUT_KEY_TAB:
                if(src->shift_pressed && evt->motion == INPUT_MOTION_PRESSED) {
                    eat_input = 1;
                    // Cycle the active window
                    ctx_order_cycle();
                }
                break;
            case KEY_RIGHT:
            case KEY_LEFT:
            case KEY_UP:
            case KEY_DOWN:
                if(evt->motion != INPUT_MOTION_RELEASED) {
                    double x_shift = 0.0;
                    double y_shift = 0.0;
                    switch(evt->key) {
                        case KEY_RIGHT:
                            x_shift += 1.0;
                            break;
                        case KEY_LEFT:
                            x_shift -= 1.0;
                            break;
                        case KEY_DOWN:
                            y_shift += 1.0;
                            break;
                        case KEY_UP:
                            y_shift -= 1.0;
                            break;
                        default:
                            break;
                    }

                    x_shift *= 0.05;
                    y_shift *= 0.05;

                    ctx_lock_order();
                    struct lens_client_ctx *active = ctx_get_active();
                    if(active != NULL) {
                        if(!src->shift_pressed && src->ctrl_pressed) {
                            active->percent_pos_x += x_shift;
                            active->percent_pos_y += y_shift;
                            if(active->percent_pos_x > 1.0) {
                                active->percent_pos_x = 1.0;
                            } else if(active->percent_pos_x < 0.0) {
                                active->percent_pos_x = 0.0;
                            }
                            if(active->percent_pos_y > 1.0) {
                                active->percent_pos_y = 1.0;
                            } else if(active->percent_pos_y < 0.0) {
                                active->percent_pos_y = 0.0;
                            }
                            eat_input = 1;
                            active->moved = 1;
                        }
                        if(!src->ctrl_pressed && src->shift_pressed) {
                            active->percent_width += x_shift;
                            active->percent_height += y_shift;
                            if(active->percent_width < 0.1) {
                                active->percent_width = 0.1;
                            } else if(active->percent_width > 1.0) {
                                active->percent_width = 1.0;
                            }
                            if(active->percent_height < 0.1) {
                                active->percent_height = 0.1;
                            } else if(active->percent_height > 1.0) {
                                active->percent_height = 1.0;
                            }
                            eat_input = 1;
                            active->resized = 1;
                        }
                    }
                    ctx_unlock_order();
                }
                break;
            default:
                break;
        }
    }

    if(!eat_input && input_buffer != NULL) {
        return lens_input_buffer_push(
                input_buffer,
                evt);
    }
    return 0;
}

static int
input_thread(void *_src)
{
    int res;

    struct input_source *src = _src;

    int input_file = open(src->path, O_RDONLY);

    while(lensd_running) {
        struct input_event evt;
        ssize_t total = 0;
        while(total < sizeof(evt)) {
            ssize_t amt = read(input_file, &evt + total, sizeof(evt)-total);
            if(amt <= 0) {
                close(input_file);
                return amt;
            }
            total += amt;
        }

        handle_input_event(src, &evt);
    }
    return 0;
}

int
input_init(void)
{
    input_buffer = lens_create_input_buffer(128);
    if(input_buffer == NULL) {
        return -ENOMEM;
    }

    ilist_init(&input_source_list);
    sem_init(&input_source_lock,1,1);
    return 0;
}

int
input_deinit(void)
{
    sem_destroy(&input_source_lock);
    ilist_node_t *iter;
    while(1) {
        iter = ilist_pop_head(&input_source_list);
        struct input_source *source =
            container_of(iter, struct input_source, list_node);

        int exitcode;
        thrd_join(source->thread, &exitcode);
        free(source->path);
        free(source);
    }
 
    lens_destroy_input_buffer(input_buffer);
    return 0;
}

int
add_input(const char *path)
{
    int res;

    struct input_source *src = malloc(sizeof(*src));
    if(src == NULL) {
        return -ENOMEM;
    }

    src->path = strdup(path);
    if(src->path == NULL) {
        free(src);
        return -ENOMEM;
    }

    res = thrd_create(&src->thread, input_thread, src);
    if(res) {
        free(src->path);
        free(src);
        return res;
    }

    while(sem_wait(&input_source_lock)) {}
    ilist_push_tail(&input_source_list, &src->list_node);
    sem_post(&input_source_lock);

    return 0;
}

static int
input_send_event_to_ctx(
        struct lens_client_ctx *ctx,
        void *_evt)
{
    struct input_event *evt = _evt;
    return lens_client_send_input_event(
            ctx->client,
            evt);
}

int
input_loop_iter(void)
{
    int res;
    for(size_t i = 0; i < MAX_INPUT_EVENTS_PER_ITER; i++) {
        struct input_event evt;
        res = lens_input_buffer_pop(
                input_buffer,
                &evt);
        if(res == 0) {
            break;
        } else if(res < 0) {
            return res;
        }

        ctx_lock_order();
        {
            struct lens_client_ctx *active = ctx_get_active();
            if(active != NULL) {
                input_send_event_to_ctx(active, &evt);
            }
        }
        ctx_unlock_order();

//      BROADCAST
//        res = foreach_lens_client(
//                input_send_event_to_ctx,
//                &evt);
//        if(res) {
//            return res;
//        }
    }
}

