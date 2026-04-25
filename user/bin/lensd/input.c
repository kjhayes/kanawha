
#include "lensd.h"
#include <lens/input_buffer.h>
#include <kanawha/input.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_INPUT_EVENTS_PER_ITER (8)

static struct lens_input_buffer *input_buffer = NULL;

struct input_source {
    const char *path;
    thrd_t thread;
};

static struct input_source
input_sources[] = {
    {
        .path = "/dev/input/ps2-mouse-0",
    },
    {
        .path = "/dev/input/ps2-kbd-0",
    },

};
#define NUM_INPUT_SOURCES (sizeof(input_sources) / sizeof(struct input_source))

// Centralized function called by all input
// source's threads
static int
handle_input_event(
        struct input_event *evt)
{
    if(input_buffer != NULL) {
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

        handle_input_event(&evt);
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
    for(size_t i = 0; i < NUM_INPUT_SOURCES; i++) {
        struct input_source *src = &input_sources[i];
        thrd_create(&src->thread, input_thread, src);
    }
    return 0;
}

int
input_deinit(void)
{
    for(size_t i = 0; i < NUM_INPUT_SOURCES; i++) {
        int exitcode;
        thrd_join(input_sources[i].thread, &exitcode);
    }
    lens_destroy_input_buffer(input_buffer);
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

        // Send a message containing this input event
        // to the active thread... (TODO)
        // For now just broadcast

        res = foreach_lens_client(
                input_send_event_to_ctx,
                &evt);
        if(res) {
            return res;
        }
    }
}

