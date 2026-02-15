#ifndef __CABIN_FBTERM__RENDER_H__
#define __CABIN_FBTERM__RENDER_H__

#include "term.h"
#include "font.h"
#include "kfb/kfb.h"

int
render_update(
        struct terminal_data *tdata,
        struct font_data *fdata,
        struct kfb_framebuffer *fb,
        int layer);

#endif
