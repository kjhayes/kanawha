
#include "render.h"
#include <errno.h>
#include <stdlib.h>
#include <lens/window.h>
#include <lens/gfx.h>

struct render_ctx
{
    enum
    {
        RENDER_CTX_TYPE_FB,
        RENDER_CTX_TYPE_LENSD,
    } type;
    union
    {
        struct
        {
            struct kfb_framebuffer *fb;
            struct fb_mode_info *minfo;
            int layer;
        } fb;
        struct 
        {
            struct lens_window *window;
        } lensd;
    };
};

struct render_ctx *
create_fb_render_ctx(struct kfb_framebuffer *fb, int layer)
{
    struct render_ctx *ctx = malloc(sizeof(struct render_ctx));
    if(ctx == NULL)
    {
        return NULL;
    }
    ctx->type = RENDER_CTX_TYPE_FB;
    ctx->fb.fb = fb;
    ctx->fb.layer = layer;
    ctx->fb.minfo = NULL;

    return ctx;
}

struct render_ctx *
create_lens_render_ctx(struct lens_window *window)
{
    struct render_ctx *ctx = malloc(sizeof(struct render_ctx));
    if(ctx == NULL)
    {
        return NULL;
    }
    ctx->type = RENDER_CTX_TYPE_LENSD;
    ctx->lensd.window = window;
    return ctx;
}

int
destroy_render_ctx(struct render_ctx *ctx)
{
    switch(ctx->type)
    {
    case RENDER_CTX_TYPE_FB:
        kfb_close_framebuffer(ctx->fb.fb);
        break;
    case RENDER_CTX_TYPE_LENSD:
        break;
    default:
        return -EINVAL;
    }
    free(ctx);
    return 0;
}

int
render_ctx_begin(
        struct terminal_data *tdata,
        struct render_ctx *ctx,
        int layer,
        struct gfx_layout *gfx,
        void **buffer,
        size_t *buflen)
{
    switch(ctx->type)
    {
    case RENDER_CTX_TYPE_FB:
    {
        if(!ctx->fb.fb->have_buffer_data)
        {
            return -EINVAL;
        }
        ctx->fb.minfo =
            kfb_load_mode_info(ctx->fb.fb, kfb_get_current_mode(ctx->fb.fb));
        if(layer >= ctx->fb.minfo->layer_count)
        {
            kfb_unload_mode_info(ctx->fb.fb, ctx->fb.minfo);
            return -ENXIO;
        }
        *gfx = ctx->fb.minfo->layer_infos[layer].layout;
        *buffer = ctx->fb.fb->buffer_data;
        *buflen = ctx->fb.minfo->buffer_size;
    }
    break;
    case RENDER_CTX_TYPE_LENSD:
        lens_window_lock_gfx(ctx->lensd.window);
        struct lens_gfx_info *info;
        info = lens_window_get_gfx_info(ctx->lensd.window);
        if(info == NULL || layer >= info->num_layers) {
            lens_window_unlock_gfx(ctx->lensd.window);
            return -EINVAL;
        }
        void *frame = lens_window_get_gfx_frame(ctx->lensd.window);
        *gfx = info->layer_layout[layer];
        *buffer = frame;
        *buflen = info->frame_size;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

int
render_ctx_end(struct terminal_data *tdata, struct render_ctx *ctx, int layer, int flush)
{
    switch(ctx->type)
    {
    case RENDER_CTX_TYPE_FB:
        kfb_unload_mode_info(ctx->fb.fb, ctx->fb.minfo);
        if(flush)
        {
            kfb_flush_framebuffer(ctx->fb.fb);
        }
        break;
    case RENDER_CTX_TYPE_LENSD:
        lens_window_unlock_gfx(ctx->lensd.window);
        if(flush) {
            lens_window_flush(ctx->lensd.window);
        }
    default:
        return -EINVAL;
    }
    return 0;
}
