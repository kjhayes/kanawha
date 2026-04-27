
#include <paint/paint.h>
#include <kfb/kfb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lensd.h"

static int full_redraw_requested = 0;
int render_mark_full_redraw(void)
{
    full_redraw_requested = 1;
    return 0;
}

int render_init(void)
{
    return 0;
}
int render_deinit(void)
{
    return 0;
}

#define DEFAULT_WIDTH (320)
#define DEFAULT_HEIGHT (240)

static struct lens_gfx_info
default_gfx_info_without_display = {
    .num_layers = 1,
    .frame_size = 4 * DEFAULT_WIDTH * DEFAULT_HEIGHT,
    .layer_layout = {
        {
            .format = GFX_FORMAT_RGBA32,
            .order = GFX_ORDER_ROW_MAJOR,
            .width = DEFAULT_WIDTH,
            .height = DEFAULT_HEIGHT,
            .stride = 4,
            .offset = 0,
        },
    },
};

static int
match_client_ctx_to_display(
        struct lens_client_ctx *ctx,
        struct display *display)
{
    int res;

    if(ctx->percent_width == 1.0 && ctx->percent_height == 1.0) {
        res = lens_client_set_gfx_info(
                ctx->client, display->default_gfx_info);
        if(res) {
            return res;
        }
    } else {
        // Need to create a custom backing
        size_t len = sizeof(struct lens_gfx_info);
        len += (display->default_gfx_info->num_layers
                * sizeof(display->default_gfx_info->layer_layout[0]));
        struct lens_gfx_info *info = malloc(len);
        if(info == NULL) {
            return -ENOMEM;
        }
        memcpy(info, display->default_gfx_info, len);
        for(int i = 0; i < info->num_layers; i++) {
            info->layer_layout[i].width *= ctx->percent_width;
            info->layer_layout[i].height *= ctx->percent_height;
        }

        res = lens_client_set_gfx_info(
                ctx->client, info);
        if(res) {
            free(info);
            return res;
        }

        free(info);
    }

    res = lens_client_sync_gfx_info(ctx->client);
    if(res) {
        return res;
    }

    return 0;
}

int render_init_ctx(
        struct lens_client_ctx *ctx)
{
    int res;
    displays_lock();
    struct display *primary = display_get_primary();
    if(primary != NULL) {
        res = match_client_ctx_to_display(ctx, primary);
        if(res) {
            displays_unlock();
            return res;
        }
    } else {
        res = lens_client_set_gfx_info(
                ctx->client, &default_gfx_info_without_display);
        if(res) {
            displays_unlock();
            return res;
        }
        res = lens_client_sync_gfx_info(ctx->client);
        if(res) {
            displays_unlock();
            return res;
        }
    }
    displays_unlock();
    return 0;
}

int render_deinit_ctx(
        struct lens_client_ctx *ctx)
{
    return 0;
}

static int
clear_display_to_background(
        struct display *disp,
        void *ign)
{
    uint32_t color = 0xFF1020FF;
    struct gfx_layout color_layout = {
        .width = 1,
        .height = 1,
        .order = GFX_ORDER_ROW_MAJOR,
        .offset = 0,
        .stride = 4,
        .format = GFX_FORMAT_RGBA32,
    };
    if(disp->fb->have_buffer_data) {
        for(int i = 0; i < disp->mode_info->layer_count; i++)
        {
            paint_blit(
                    disp->fb->buffer_data,
                    disp->mode_info->buffer_size,
                    disp->mode_info->layer_infos[i].layout.width,
                    disp->mode_info->layer_infos[i].layout.height,
                    0,
                    0,
                    &disp->mode_info->layer_infos[i].layout,
                    &color,
                    4,
                    1, 1,
                    0, 0,
                    &color_layout
                    );
        }
    }
}

static int
clear_all_displays(void)
{
    return foreach_display(
            clear_display_to_background,
            NULL);
}

struct render_loop_ctx {
    int flush_requests;
    unsigned int flush_visible : 1;
    unsigned int window_moved : 1;
    unsigned int window_resized : 1;
    unsigned int force : 1;
};

static int
render_loop_check_contextes(
        struct lens_client_ctx *ctx,
        void *_render_ctx)
{
    int res;

    struct render_loop_ctx *render_ctx = _render_ctx;
    if(lens_client_requested_flush(ctx->client))
    {
        render_ctx->flush_requests++;
        render_ctx->flush_visible = 1;
    }

    render_ctx->window_moved |= ctx->moved;
    ctx->moved = 0;
    render_ctx->window_resized |= ctx->resized;
    if(ctx->resized) {
        displays_lock();
        struct display *primary = display_get_primary();
        res = match_client_ctx_to_display(
                ctx,
                primary);
        displays_unlock();
    }
    ctx->resized = 0;

    return 0;
}

struct render_window_ctx {
    struct lens_client_ctx *client_ctx;
    struct lens_gfx_info *window_info;
    void *window_frame;
    unsigned int force : 1;
};

static int
render_loop_render_ctx_onto_display(
        struct display *display,
        void *_ctx)
{
    struct render_window_ctx *ctx = _ctx;

    struct lens_gfx_info *info = ctx->window_info;
    void *frame = ctx->window_frame;

    struct fb_mode_info *mode_info = display->mode_info;
    struct kfb_framebuffer *fb = display->fb;

    if(fb->have_buffer_data) {
        if(mode_info->layer_count == info->num_layers) {
            int num_layers = mode_info->layer_count;
            for(int i = 0; i < mode_info->layer_count; i++) {
                size_t to_width = mode_info->layer_infos[i].layout.width
                                * ctx->client_ctx->percent_width;
                size_t to_height = mode_info->layer_infos[i].layout.height
                                 * ctx->client_ctx->percent_height;
                size_t to_x_offset = mode_info->layer_infos[i].layout.width
                                   * ctx->client_ctx->percent_pos_x;
                size_t to_y_offset = mode_info->layer_infos[i].layout.height
                                   * ctx->client_ctx->percent_pos_y;
                if(i < info->num_layers) {
                    paint_blit(
                            fb->buffer_data,
                            mode_info->buffer_size,
                            to_width,
                            to_height,
                            to_x_offset,
                            to_y_offset,
                            &mode_info->layer_infos[i].layout,
                            frame,
                            ctx->window_info->frame_size,
                            info->layer_layout[i].width,
                            info->layer_layout[i].height,
                            0, 0,
                            &info->layer_layout[i]
                            );
                }
            }
        } else {
            for(int il = 0; il < info->num_layers; il++) {
                struct gfx_layout *i_layout = &info->layer_layout[il];
                for(int ol = 0; ol < mode_info->layer_count; ol++) {
                    struct gfx_layout *o_layout = &mode_info->layer_infos[ol].layout;
                    size_t to_width = o_layout->width * ctx->client_ctx->percent_width;
                    size_t to_height = o_layout->height * ctx->client_ctx->percent_height; 
                    size_t to_x_offset = o_layout->width * ctx->client_ctx->percent_pos_x;
                    size_t to_y_offset = o_layout->height * ctx->client_ctx->percent_pos_y;
                    paint_blit(
                            fb->buffer_data,
                            mode_info->buffer_size,
                            to_width,
                            to_height,
                            to_x_offset,
                            to_y_offset,
                            o_layout,
                            frame,
                            ctx->window_info->frame_size,
                            i_layout->width,
                            i_layout->height,
                            0, 0,
                            i_layout
                            );
                }
            }
        }
    }
    return 0;
}

static int
render_loop_render_ctx(
        struct lens_client_ctx *ctx,
        void *_render_ctx)
{
    struct render_loop_ctx *render_ctx = _render_ctx;

    lens_client_lock_gfx(ctx->client);

    struct lens_gfx_info *info = lens_client_get_gfx_info(ctx->client);
    void *frame = lens_client_get_gfx_frame(ctx->client);

    struct render_window_ctx w_ctx = {
        .window_info = info,
        .window_frame = frame,
        .client_ctx = ctx,
        .force = render_ctx->force,
    };

    foreach_display(
            render_loop_render_ctx_onto_display,
            &w_ctx);

    lens_client_unlock_gfx(ctx->client);

    return 0;
}

static int
render_loop_ack_flushes(
        struct lens_client_ctx *ctx,
        void *_render_ctx)
{
    return lens_client_ack_flush(ctx->client);
}

int render_loop_iter(void)
{
    int res;

    struct render_loop_ctx ctx = {
        .flush_requests = 0,
        .flush_visible = 0,
        .window_resized = 0,
        .window_moved = 0,
        .force = __atomic_fetch_and(&full_redraw_requested, 0, __ATOMIC_SEQ_CST),
    };

    res = foreach_lens_client(
            render_loop_check_contextes,
            &ctx);
    if(res) {
        return res;
    }

    if(ctx.flush_requests > 0 || ctx.window_moved || ctx.window_resized || ctx.force) {

        if(ctx.flush_visible || ctx.window_moved || ctx.window_resized || ctx.force) {
            if(ctx.window_moved || ctx.window_resized || ctx.force) {
                clear_all_displays();
            }

            // Re-render
            res = foreach_lens_client_back_to_front(
                    render_loop_render_ctx,
                    &ctx);
            if(res) {
                fprintf(stderr, "lensd: failed to render all windows!\n");
            }

            // Flush
            display_flush_all();
        }

        // Ack Flushes
        res = foreach_lens_client(
                render_loop_ack_flushes,
                &ctx);
        if(res) {
            fprintf(stderr, "lensd: failed to ack client flushes!\n");
            return res;
        }
    }

    return 0;
}

