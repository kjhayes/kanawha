
#include <kfb/kfb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "lensd.h"

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

int render_init_ctx(
        struct lens_client_ctx *ctx)
{
    int res;
    displays_lock();

    struct display *primary = display_get_primary();
    if(primary != NULL) {
        res = lens_client_set_gfx_info(
                ctx->client, primary->default_gfx_info);
        if(res) {
            displays_unlock();
            return res;
        }
        displays_unlock();
    } else {
        displays_unlock();
        res = lens_client_set_gfx_info(
                ctx->client, primary->default_gfx_info);
        if(res) {
            return res;
        }
    }

    res = lens_client_sync_gfx_info(ctx->client);
    if(res) {
        return res;
    }
    return 0;
}

int render_deinit_ctx(
        struct lens_client_ctx *ctx)
{
    return 0;
}

struct render_loop_ctx {
    int flush_requests;
    unsigned int flush_visible : 1;
};

static int
render_loop_count_flush_request(
        struct lens_client_ctx *ctx,
        void *_render_ctx)
{
    struct render_loop_ctx *render_ctx = _render_ctx;
    if(lens_client_requested_flush(ctx->client)) {
        render_ctx->flush_requests++;
        render_ctx->flush_visible = 1; // TODO actually figure out if this window
                                       // is visible or not...
        // printf("lensd: flush requested!\n");
    }
    return 0;
}

struct render_window_ctx {
    struct lens_gfx_info *window_info;
    void *window_frame;
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
        int num_layers = mode_info->layer_count;
        for(int i = 0; i < mode_info->layer_count; i++) {
           //  printf("render_loop_render_ctx: rendering to layer %d\n", i);
            if(i < info->num_layers) {
                kfb_blit(
                        fb->buffer_data,
                        mode_info->layer_infos[i].layout.width,
                        mode_info->layer_infos[i].layout.height,
                        0, // offset x
                        0, // offset y
                        &mode_info->layer_infos[i].layout,
                        frame,
                        info->layer_layout[i].width,
                        info->layer_layout[i].height,
                        0, 0,
                        &info->layer_layout[i]
                        );
            } else {
                uint32_t color = 0xFF000000;
                struct gfx_layout color_layout = {
                    .width = 1,
                    .height = 1,
                    .order = GFX_ORDER_ROW_MAJOR,
                    .offset = 0,
                    .stride = 4,
                    .format = GFX_FORMAT_RGBA32,
                };
                kfb_blit(
                        fb->buffer_data,
                        mode_info->layer_infos[i].layout.width,
                        mode_info->layer_infos[i].layout.height,
                        0, // offset x
                        0, // offset y
                        &mode_info->layer_infos[i].layout,
                        &color,
                        1, 1,
                        0, 0,
                        &color_layout
                        );
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
    };

    res = foreach_lens_client(
            render_loop_count_flush_request,
            &ctx);
    if(res) {
        return res;
    }

    if(ctx.flush_requests > 0) {

        // Re-render
        res = foreach_lens_client_back_to_front(
                render_loop_render_ctx,
                &ctx);
        if(res) {
            fprintf(stderr, "lensd: failed to render all windows!\n");
        }

        // Flush
        display_flush_all();

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

