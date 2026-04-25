#ifndef __KANAWHA__LENSD_H__
#define __KANAWHA__LENSD_H__

#include <lens/lens.h>
#include <lens/server.h>
#include <unistd.h>
#include <threads.h>
#include <ilist.h>

extern int lensd_running;

struct lens_client_ctx
{
    struct lens_client *client;

    double percent_pos_x;
    double percent_pos_y;

    double percent_width;
    double percent_height;

    ilist_node_t list_node;
};

int ctx_init(void);
int ctx_deinit(void);
int ctx_loop_iter();

struct display
{
    char *path;

    struct kfb_framebuffer *fb;

    int mode;
    struct fb_mode_info *mode_info;

    struct lens_gfx_info *default_gfx_info;

    ilist_node_t list_node;
};

int display_init(void);
int display_deinit(void);
int add_display(const char *path, int mode);
int foreach_display(
        int(*callback)(struct display *disp, void *state),
        void *state);
int display_flush_all(void);
int displays_lock(void);
int displays_unlock(void);
struct display *display_get_primary(void);

int render_init(void);
int render_deinit(void);
int render_init_ctx(struct lens_client_ctx *ctx);
int render_deinit_ctx(struct lens_client_ctx *ctx);
int render_loop_iter(void);

int listener_init(void);
int listener_deinit(void);

int input_init(void);
int input_deinit(void);
int input_loop_iter(void);
int add_input(const char *path);

int add_lens_client(struct lens_client *client);
int remove_lens_client(struct lens_client_ctx *ctx);

int foreach_lens_client(
        int(*callback)(struct lens_client_ctx *ctx, void *state),
        void *state);
int foreach_lens_client_back_to_front(
        int(*callback)(struct lens_client_ctx *ctx, void *state),
        void *state);

#endif
