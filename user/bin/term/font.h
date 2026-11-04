#ifndef __CABIN_FBTERM__FONT_H__
#define __CABIN_FBTERM__FONT_H__

#include "color.h"
#include "kfb/kfb.h"
#include <stddef.h>
#include <stdint.h>

struct glyph_data
{
    struct kfb_image *fg;
    struct kfb_image *bg;
};

struct font_data
{
    size_t width;
    size_t height;
    size_t error_glyph;
    size_t num_glyphs;
    struct glyph_data *glyphs;
};

struct font_data *
load_default_font(void);
struct font_data *
load_font_from_buffer(void *buffer, size_t buflen);
struct font_data *
load_font_from_file(const char *path);
void
unload_font(struct font_data *fdata);

#endif
