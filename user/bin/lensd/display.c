
#include "display.h"
#include "util.h"

#include <kfb/kfb.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct display
{
    char *path;

    struct kfb_framebuffer *fb;

    int mode;
    struct fb_mode_info *mode_info;

    list_node_t list_node;
};

sem_t display_lock;
list_t display_list;
struct display *primary_display = NULL;

int
display_init(void)
{
    sem_init(&display_lock, 1, 1);
    list_init(&display_list);
    return 0;
}

int
display_deinit(void)
{
    sem_destroy(&display_lock);

    list_node_t *iter;
    while(1) {
        iter = list_pop_head(&display_list);
        struct display *disp;
        disp = container_of(iter, struct display, list_node);

        kfb_close_framebuffer(disp->fb);
        free(disp);
    }

    return 0;
}

int
add_display(const char *path, int mode)
{
    int res;

    struct display *disp;
    disp = malloc(sizeof(*disp));
    if(disp == NULL) {
        return -ENOMEM;
    }
    memset(disp, 0, sizeof(*disp));

    disp->path = strdup(path);
    if(disp->path == NULL) {
        free(disp);
        return -ENOMEM;
    }

    disp->fb = kfb_open_framebuffer(path);
    if(disp->fb == NULL) {
        free(disp->path);
        free(disp);
        return -ENXIO;
    }

    disp->mode = mode;
    disp->mode_info =
        kfb_load_mode_info(
                disp->fb,
                disp->mode);
    if(disp->mode_info == NULL) {
        kfb_close_framebuffer(disp->fb);
        free(disp->path);
        free(disp);
        return res;
    }
    disp->mode = mode;
    res = kfb_set_current_mode(
            disp->fb, mode);
    if(res) {
        kfb_unload_mode_info(
                disp->fb,
                disp->mode_info);
        kfb_close_framebuffer(disp->fb);
        free(disp->path);
        free(disp);
        return res;
    }

    int num_layers = disp->mode_info->layer_count;
    while(sem_wait(&display_lock)) {}
    list_push_tail(&display_list, &disp->list_node);
    if(primary_display == NULL) {
        primary_display = disp;
    }
    sem_post(&display_lock);
    return 0;
}

int foreach_display(
        int(*callback)(struct display *disp, void *state),
        void *state)
{
    while(sem_wait(&display_lock)) {}
    list_node_t *iter;
    iter = list_begin(&display_list);
    while(iter) {
        struct display *disp = container_of(iter, struct display, list_node);
        (*callback)(disp, state);
        iter = list_next(&display_list, iter);
    }
    sem_post(&display_lock);
    return 0;
}

static int
display_callback_flush(
        struct display *disp,
        void *state)
{
    return kfb_flush_framebuffer(disp->fb);
}

int
display_flush_all(void)
{
    return foreach_display(
            display_callback_flush,
            NULL);
}

int
displays_lock(void) {
    while(sem_wait(&display_lock)) {}
}
int
displays_unlock(void) {
    sem_post(&display_lock);
}

struct display *
display_get_primary(void)
{
    return primary_display;
}

static int
add_display_callback(
        const char *path)
{
    add_display(path, 0);
    return 0;
}

int
add_all_displays(const char *dir_path) {
    foreach_in_dir(dir_path, add_display_callback);
}

