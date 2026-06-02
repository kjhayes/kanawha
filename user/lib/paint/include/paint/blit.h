#ifndef __KANAWHA_PAINT_BLIT_H__
#define __KANAWHA_PAINT_BLIT_H__

#include <paint/convert.h>

#include <kanawha/gfx.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern const char PAINT_ASCII_DOWNSAMPLE_TABLE[512];

static inline int
paint_sample(
        void *to_pixel,
        unsigned long to_pixel_format,
        void *from_buffer,
        size_t from_buflen,
        size_t from_offset_x,
        size_t from_offset_y,
        size_t from_width,
        size_t from_height,
        struct gfx_layout *from_layout)
{
    // Do the simplest thing and sample the top left
    // pixel only 

    int res;

    from_buffer += from_layout->offset;

    if(from_width == 1 && from_height == 1) {
        void *from_pixel;
        if(from_layout->order == GFX_ORDER_ROW_MAJOR) {
            from_pixel = from_buffer + (((from_offset_x) + ((from_offset_y) * from_layout->width)) * from_layout->stride);
        } else {
            from_pixel = from_buffer + (((from_offset_y) + ((from_offset_x) * from_layout->height)) * from_layout->stride);
        }
        return paint_convert_pixel(
                to_pixel_format,
                to_pixel,
                from_layout->format,
                from_pixel);
    }

    uint32_t rgba_grid[from_width * from_height];

    for(size_t fyi = 0; fyi < from_height; fyi++) {
    for(size_t fxi = 0; fxi < from_width; fxi++) {

        void *from_pixel;
        if(from_layout->order == GFX_ORDER_ROW_MAJOR) {
            from_pixel = from_buffer + (((fxi + from_offset_x) + ((fyi + from_offset_y) * from_layout->width)) * from_layout->stride);
        } else {
            from_pixel = from_buffer + (((fyi + from_offset_y) + ((fxi + from_offset_x) * from_layout->height)) * from_layout->stride);
        }

        res = paint_convert_pixel(
                GFX_FORMAT_RGBA32,
                &rgba_grid[fxi + (fyi * from_width)],
                from_layout->format,
                from_pixel);
        if(res) {
            return res;
        }
    }}

    // Downscale the RGBA grid

    switch(to_pixel_format) {
        case GFX_FORMAT_VGA_CHAR:
        case GFX_FORMAT_ASCII:
            {
                // Compute a "brightness grid"
                uint16_t avg_br = 0;
                uint8_t br_grid[from_width * from_height];
                for(int i = 0; i < from_width * from_height; i++) {
                    uint32_t br = 0;
                    uint8_t *rgb = (uint8_t*)&rgba_grid[i];
                    uint8_t *a = rgb + 3;
                    if(*a < 0x80) {
                        br_grid[i] = 0;
                        continue;
                    }
                    for(int c = 0; c < 3; c++) {
                        br += rgb[c];
                    }
                    br /= 3;
                    br_grid[i] = br;
                    avg_br += br;
                }
                avg_br /= (from_width * from_height);

                uint16_t brightness[3*3] = {0};
                size_t br_w = ((double)from_width/3);
                size_t br_h = ((double)from_height/3);
                if(br_w < 1) {
                    br_w = 1;
                }
                if(br_h < 1) {
                    br_h = 1;
                }
                for(size_t by = 0; by < 3; by++) {
                for(size_t bx = 0; bx < 3; bx++) {
                    double px = ((double)bx/3);
                    double py = ((double)by/3);
                    size_t br_x = px * from_width;
                    size_t br_y = py * from_height;

                    int n = 0;
                    for(size_t y = br_y; y < (br_y + br_h) && y < from_height; y++) {
                    for(size_t x = br_x; x < (br_x + br_w) && x < from_width; x++) {
                        brightness[bx + (by * 2)] += br_grid[x + (y * from_width)];
                        n++;
                    }}
                    if(n > 0) {
                        brightness[bx + (by * 2)] /= n;
                    }
                }}

                uint16_t index = 0;
                int popcount = 0;
                for(size_t i = 0; i < 3*3; i++) {
                    if(brightness[i] >= 0x10 && brightness[i] > avg_br) {
                        popcount++;
                        index |= (1<<(8-i));
                    }
                }

                char c = PAINT_ASCII_DOWNSAMPLE_TABLE[index];
                if(c == 0) {
                    for(int i = 0; i < 9; i++) {
                        char near = PAINT_ASCII_DOWNSAMPLE_TABLE[index ^ (1<<i)];
                        if(near != 0) {
                            c = near;
                            break;
                        }
                    }
                }
                if(c == 0) {
                    if(popcount < 4) {
                        c = ' ';
                    } else {
                        c = '@';
                    }
                }
                *((char*)to_pixel) = c;
                return 0;
            }
            break;
        default:
            break;
    }

    // Average the RGBA values
    uint32_t r = 0;
    uint32_t g = 0;
    uint32_t b = 0;
    uint32_t a = 0;
    for(size_t i = 0; i < from_width * from_height; i++) {
        uint32_t rgba = rgba_grid[i];
        r += (rgba>>0) & 0xFF;
        g += (rgba>>8) & 0xFF;
        b += (rgba>>16) & 0xFF;
        a += (rgba>>24) & 0xFF;
    }

    r /= (from_width * from_height);
    g /= (from_width * from_height);
    b /= (from_width * from_height);
    a /= (from_width * from_height);

    uint32_t final_rgba = (r<<0) | (g<<8) | (b<<16) | (a<<24);

    return paint_convert_pixel(
            to_pixel_format,
            to_pixel,
            GFX_FORMAT_RGBA32,
            &final_rgba);
}

static inline int
paint_blit_with_transform(
        void *to,
        size_t to_len,
        size_t to_width,
        size_t to_height,
        ssize_t to_offset_x,
        ssize_t to_offset_y,
        struct gfx_layout *to_layout,
        void *from,
        size_t from_len,
        size_t from_width,
        size_t from_height,
        ssize_t from_offset_x,
        ssize_t from_offset_y,
        struct gfx_layout *from_layout,
        void *xform_state,
        int(*xform)(void *pix, unsigned long format, void *state)
        )
{
    to += to_layout->offset;

    double prop_w = ((double)1.0 / to_width);
    double prop_h = ((double)1.0 / to_height);

    size_t fw = prop_w * from_width;
    if(fw < 1) {
        fw = 1;
    }
    size_t fh = prop_h * from_height;
    if(fh < 1) {
        fh = 1;
    }

    for(size_t tyi = 0; tyi < to_height; tyi++) {
    for(size_t txi = 0; txi < to_width; txi++) {

        void *to_data;
        if(to_layout->order == GFX_ORDER_ROW_MAJOR) {
            to_data = to + (((txi + to_offset_x) + ((tyi + to_offset_y) * to_layout->width)) * to_layout->stride);
        } else {
            to_data = to + (((tyi + to_offset_y) + ((txi + to_offset_x) * to_layout->height)) * to_layout->stride);
        }

        double prop_x = ((double)txi / to_width);
        double prop_y = ((double)tyi / to_height);

        size_t fxi = prop_x * from_width;
        size_t fyi = prop_y * from_height;

        if(fxi + fw > from_width) {
            fw = from_width - fxi;
        }
        if(fyi + fh > from_height) {
            fh = from_height - fyi;
        }

        paint_sample(
                to_data,
                to_layout->format,
                from,
                from_len,
                from_offset_x + fxi,
                from_offset_y + fyi,
                fw,
                fh,
                from_layout);

        if(xform) {
            (*xform)(to_data, to_layout->format, xform_state);
        }
    }}

    return 0;
}

static inline int
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
         struct gfx_layout *from_layout)
{
    return paint_blit_with_transform(
            to,
            to_len,
            to_width,
            to_height,
            to_off_x,
            to_off_y,
            to_layout,
            from,
            from_len,
            from_width,
            from_height,
            from_off_x,
            from_off_y,
            from_layout,
            NULL,
            NULL);
}

#endif
