#ifndef __KANAWHA__PAINT_PAINT_H__
#define __KANAWHA__PAINT_PAINT_H__

#include <kanawha/gfx.h>
#include <kanawha/types.h>

ssize_t paint_gfx_format_pixel_size(unsigned long format);

int
paint_convert_pixel(
        unsigned long to_format,
        void *to_data,
        unsigned long from_format,
        void *from_data);

int
paint_blit(
        void *to,
        size_t to_len,
        size_t to_width,
        size_t to_height,
        ssize_t to_off_x,
        ssize_t to_off_y,
        struct gfx_layout *to_layout,
        void *from,
        size_t from_len,
        size_t from_width,
        size_t from_height,
        ssize_t from_off_x,
        ssize_t from_off_y,
        struct gfx_layout *from_layout
        );

int
paint_blit_with_transform(
        void *to,
        size_t to_len,
        size_t to_width,
        size_t to_height,
        ssize_t to_off_x,
        ssize_t to_off_y,
        struct gfx_layout *to_layout,
        void *from,
        size_t from_len,
        size_t from_width,
        size_t from_height,
        ssize_t from_off_x,
        ssize_t from_off_y,
        struct gfx_layout *from_layout,
        void *xform_state,
        int(*xform)(void *pix, unsigned long format, void *state)
        );



#endif
