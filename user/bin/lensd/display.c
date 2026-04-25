
#include "lensd.h"
#include <ilist.h>
#include <kfb/kfb.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

sem_t display_lock;
ilist_t display_list;
struct display *primary_display = NULL;

int
display_init(void)
{
    sem_init(&display_lock, 1, 1);
    ilist_init(&display_list);
    return 0;
}

int
display_deinit(void)
{
    sem_destroy(&display_lock);

    ilist_node_t *iter;
    while(1) {
        iter = ilist_pop_head(&display_list);
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

    size_t info_len = sizeof(*disp->default_gfx_info)
        + (num_layers * sizeof(disp->default_gfx_info->layer_layout[0]));
    struct lens_gfx_info *info = malloc(info_len);
    if(info == NULL) {
        kfb_unload_mode_info(
                disp->fb,
                disp->mode_info);
        kfb_close_framebuffer(disp->fb);
        free(disp->path);
        free(disp);
        return -ENOMEM;
    }

    info->frame_size = disp->mode_info->buffer_size;
    info->num_layers = num_layers;
    for(int i = 0; i < num_layers; i++) {
        struct gfx_layout *layer = &info->layer_layout[i];
        *layer = disp->mode_info->layer_infos[i].layout;
    }

    disp->default_gfx_info = info;

    while(sem_wait(&display_lock)) {}
    ilist_push_tail(&display_list, &disp->list_node);
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
    ilist_node_t *iter;
    ilist_for_each(iter, &display_list) {
        struct display *disp = container_of(iter, struct display, list_node);
        (*callback)(disp, state);
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

