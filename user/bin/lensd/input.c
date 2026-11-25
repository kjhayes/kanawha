
#include "util.h"
#include <kanawha/input.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ilist.h>
#include <string.h>
#include <stdlib.h>
#include <semaphore.h>

#define MAX_INPUT_EVENTS_PER_ITER (8)

// static struct lens_input_buffer *input_buffer = NULL;

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
            // TODO
            default:
                break;
        }
    }

    // TODO: Actually send the input to a window

    return 0;
}

static int
input_thread(void *_src)
{
    int res;

    struct input_source *src = _src;

    int input_file = open(src->path, O_RDONLY);
    if(input_file < 0) {
        INFO("failed to open input device \"%s\"!\n",
                src->path);
        return -EINVAL;
    }

    while(lensd_running) {
        struct input_event evt;
        ssize_t total = 0;
        while(total < sizeof(evt)) {
            ssize_t amt = read(input_file, &evt + total, sizeof(evt)-total);
            if(amt <= 0) {
                INFO("input_thread error closing!\n");
                close(input_file);
                return amt;
            }
            total += amt;
        }

        handle_input_event(src, &evt);
    }

    INFO("input_thread shutting down!\n");
    close(input_file);
    return 0;
}

int
input_init(void)
{
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
 
//    lens_destroy_input_buffer(input_buffer);
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
add_input_callback(
        const char *path)
{
    INFO("adding input: %s\n", path);
    add_input(path);
    return 0;
}

int
add_all_inputs(const char *dir_path) {
    foreach_in_dir(dir_path, add_input_callback);
}

