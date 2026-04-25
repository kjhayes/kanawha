
#include <paint/paint.h>
#include <kanawha/gfx.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int
paint_blit(void *to,
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

int
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
    int res;

    // Clipping
    if(to_offset_x >= to_layout->width)
    {
        return 0;
    }
    if(to_offset_y >= to_layout->height)
    {
        return 0;
    }
    if(from_offset_x >= from_layout->width)
    {
        return 0;
    }
    if(from_offset_y >= from_layout->height)
    {
        return 0;
    }

    //
    if(to_width == 0 || to_height == 0)
    {
        return -EINVAL;
    }
    if(from_width == 0 || from_height == 0)
    {
        return -EINVAL;
    }

#undef FROM_OFFSET
#define FROM_OFFSET(__px, __py)                                                \
    from_layout->offset +                                                      \
        (((size_t)((__px * from_width) + from_offset_x)) *                     \
         from_layout->stride) +                                                \
        (((size_t)((__py * from_height) + from_offset_y)) *                    \
         from_layout->stride * from_layout->width)

#undef TO_OFFSET
#define TO_OFFSET(__x, __y)                                                    \
    to_layout->offset + (((size_t)(__x)) * to_layout->stride) +                \
        (((size_t)(__y)) * to_layout->stride * to_layout->width)

    for(size_t y = 0; y < to_height; y++)
    {
        for(size_t x = 0; x < to_width; x++)
        {

            uint32_t cur_rgba = 0;

            double px = (double)x / (double)to_width;
            double py = (double)y / (double)to_height;

            size_t from_offset = FROM_OFFSET(px, py);
            uint8_t *from_data = &((uint8_t *)from)[from_offset];

            size_t to_offset = TO_OFFSET(to_offset_x + x, to_offset_y + y);
            if(to_offset_x + x >= to_layout->width)
            {
                break;
            }
            if(to_offset_y + y >= to_layout->height)
            {
                break;
            }
            uint8_t *to_data = &((uint8_t *)to)[to_offset];

            if(xform)
            {
                do {
                    ssize_t pixel_len =
                        paint_gfx_format_pixel_size(to_layout->format);
                    if(pixel_len < 0) {
                        break;
                    }
                    uint8_t pixbuf[pixel_len];

                    res = paint_convert_pixel(
                            to_layout->format,
                            to_data,
                            from_layout->format,
                            from_data);
                    if(res) {
                        break;
                    }

                    (*xform)(pixbuf, to_layout->format, xform_state);

                    memcpy(to_data, pixbuf, pixel_len);

                } while(0);
            }
            else
            {
                unsigned long from_format = from_layout->format;
                unsigned long to_format = to_layout->format;
                res = paint_convert_pixel(
                        to_layout->format,
                        to_data,
                        from_layout->format,
                        from_data);
                if(res)
                {
                    printf("kfb: failed to convert pixel to=%d, from=%d!\n",
                           (int)to_format,
                           (int)from_format);
                }
            }
        }
    }

    return 0;

}

