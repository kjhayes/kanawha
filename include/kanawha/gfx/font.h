#ifndef __KANAWHA__GFX_FONT_H__
#define __KANAWHA__GFX_FONT_H__

#include <kanawha/types.h>
#include <kanawha/gfx/layout.h>

struct font {
    struct gfx_layout layout; 

    size_t num_chars;
    size_t char_byte_stride;
    size_t font_data_size;

    void *font_data;
};

extern struct font kanawha_default_font;

#endif
