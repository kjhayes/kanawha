#ifndef __CABIN_FBTERM__RENDER_H__
#define __CABIN_FBTERM__RENDER_H__

#include "font.h"
#include "kfb/kfb.h"
#include "term.h"
#include <lens/window.h>

struct render_ctx;

struct render_ctx *
create_fb_render_ctx(struct kfb_framebuffer *fb, int layer);

struct render_ctx *
create_lens_render_ctx(struct lens_window *win);

int
destroy_render_ctx(struct render_ctx *ctx);

int
render_update(struct terminal_data *tdata,
              struct font_data *fdata,
              struct render_ctx *ctx);

int
render_ctx_begin(struct render_ctx *ctx,
                 int layer,
                 struct gfx_layout *gfx,
                 void **buffer,
                 size_t *buflen);
int
render_ctx_end(struct render_ctx *ctx, int layer, int flush);

#endif
