#ifndef __KANAWHA__VGA_FONT_H__
#define __KANAWHA__VGA_FONT_H__

#include <drivers/vga/vga.h>
#include <kanawha/gfx/font.h>

int
vga_load_glyph(struct vga_dev *dev,
               char c,
               const uint8_t *glyph,
               size_t height,
               unsigned int character_set);

int
vga_load_font(struct vga_dev *vga,
              unsigned int character_set,
              struct font *font);

#endif
