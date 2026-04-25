
#include <ctype.h>
#include <errno.h>
#include <paint/paint.h>
#include <kanawha/fb.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <kfb/kfb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
__kfb_set_mode_info(struct kfb_framebuffer *fb, int mode)
{
    char strbuf[64];
    snprintf(strbuf, 64, "%d", mode);
    strbuf[64 - 1] = '\0';

    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);

    size_t len = strlen(strbuf);

    ssize_t total_written = 0;
    while(total_written < len)
    {
        ssize_t written = kanawha_sys_write(fb->mode_info_file,
                                            strbuf + total_written,
                                            len - total_written);
        if(written < 0)
        {
            // Error
            return written;
        }
        total_written += written;
        if(written == 0)
        {
            break;
        }
    }
    kanawha_sys_flush(fb->mode_info_file, 0);
    return 0;
}

static int
__kfb_set_mode(struct kfb_framebuffer *fb, int mode)
{
    char strbuf[64];
    snprintf(strbuf, 64, "%d", mode);
    strbuf[64 - 1] = '\0';

    kanawha_sys_seek(fb->mode_set_file, 0, SEEK_SET);

    size_t len = strlen(strbuf);

    ssize_t total_written = 0;
    while(total_written < len)
    {
        ssize_t written = kanawha_sys_write(fb->mode_set_file,
                                            strbuf + total_written,
                                            len - total_written);
        if(written < 0)
        {
            // Error
            return written;
        }
        total_written += written;
        if(written == 0)
        {
            break;
        }
    }
    kanawha_sys_flush(fb->mode_set_file, 0);
    return 0;
}

static struct fb_mode_info *
__kfb_load_mode_info(struct kfb_framebuffer *fb)
{
    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);
    size_t size = kanawha_sys_seek(fb->mode_info_file, 0, SEEK_END);

    if(size == 0)
    {
        // Mode does not exist
        return NULL;
    }

    struct fb_mode_info *info = malloc(size);
    if(info == NULL)
    {
        return NULL;
    }
    memset(info, 0, size);

    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);

    size_t total_read = 0;
    while(total_read < size)
    {
        ssize_t read = kanawha_sys_read(fb->mode_info_file, info, size);
        if(read < 0)
        {
            free(info);
            return NULL;
        }
        total_read += read;
        if(read == 0)
        {
            break;
        }
    }

    return info;
}

static int
__kfb_unload_mode_info(struct fb_mode_info *info)
{
    free(info);
    return 0;
}

struct kfb_framebuffer *
kfb_open_framebuffer(const char *path)
{
    int res;

    fd_t buffer_file;

#ifdef PATHBUFLEN
#undef PATHBUFLEN
#endif
#define PATHBUFLEN 128
    char path_buf[PATHBUFLEN];

    snprintf(path_buf, PATHBUFLEN, "%s", path);
    path_buf[PATHBUFLEN - 1] = '\0';
    res = kanawha_sys_open(path_buf,
                           FILE_PERM_READ | FILE_PERM_WRITE,
                           0,
                           &buffer_file);
    if(res)
    {
        return NULL;
    }

    struct kfb_framebuffer *fb = kfb_attach_framebuffer(buffer_file);
    kanawha_sys_close(buffer_file);
    return fb;
}

int
kfb_close_framebuffer(struct kfb_framebuffer *fb)
{
    return kfb_deattach_framebuffer(fb);
}

struct kfb_framebuffer *
kfb_attach_framebuffer(fd_t dev_file)
{
    int res;

    fd_t buffer_file;
    fd_t mode_set_file;
    fd_t mode_info_file;

    buffer_file = dup(dev_file);

    mode_set_file = buffer_file;
    res = kanawha_sys_open("mode",
                           FILE_PERM_READ | FILE_PERM_WRITE,
                           FILE_MODE_OPEN_RELATIVE,
                           &mode_set_file);
    if(res)
    {
        kanawha_sys_close(buffer_file);
        return NULL;
    }

    mode_info_file = buffer_file;
    res = kanawha_sys_open("info",
                           FILE_PERM_READ | FILE_PERM_WRITE,
                           FILE_MODE_OPEN_RELATIVE,
                           &mode_info_file);
    if(res)
    {
        kanawha_sys_close(buffer_file);
        kanawha_sys_close(mode_set_file);
        return NULL;
    }

    struct kfb_framebuffer *fb = malloc(sizeof(struct kfb_framebuffer));
    if(fb == NULL)
    {
        kanawha_sys_close(buffer_file);
        kanawha_sys_close(mode_set_file);
        kanawha_sys_close(mode_info_file);
        return NULL;
    }
    memset(fb, 0, sizeof(struct kfb_framebuffer));

    fb->buffer_file = buffer_file;
    fb->mode_set_file = mode_set_file;
    fb->mode_info_file = mode_info_file;

    int current_mode = kfb_get_current_mode(fb);
    if(current_mode < 0)
    {
        kanawha_sys_close(fb->buffer_file);
        kanawha_sys_close(fb->mode_set_file);
        kanawha_sys_close(fb->mode_info_file);
        free(fb);
        return NULL;
    }

    __kfb_set_mode_info(fb, current_mode);
    struct fb_mode_info *info = __kfb_load_mode_info(fb);
    if(info == NULL)
    {
        kanawha_sys_close(fb->buffer_file);
        kanawha_sys_close(fb->mode_set_file);
        kanawha_sys_close(fb->mode_info_file);
        free(fb);
        return NULL;
    }

    fb->current_mode_info = info;

    res = kanawha_sys_mmap(fb->buffer_file,
                           0,
                           (void **)&fb->buffer_data,
                           (info->buffer_size + 0xFFF) & ~0xFFF,
                           MMAP_SHARED | MMAP_PROT_READ | MMAP_PROT_WRITE);
    if(res)
    {
        fb->have_buffer_data = 0;
    }
    else
    {
        fb->have_buffer_data = 1;
    }

    return fb;
}
int
kfb_deattach_framebuffer(struct kfb_framebuffer *fb)
{
    kanawha_sys_close(fb->buffer_file);
    kanawha_sys_close(fb->mode_set_file);
    kanawha_sys_close(fb->mode_info_file);
    if(fb->current_mode_info != NULL)
    {
        __kfb_unload_mode_info(fb->current_mode_info);
    }
    if(fb->buffer_data != NULL)
    {
        kanawha_sys_munmap(fb->buffer_data);
    }
    free(fb);
    return 0;
}

struct fb_mode_info *
kfb_load_mode_info(struct kfb_framebuffer *fb, int mode)
{
    int res;
    res = __kfb_set_mode_info(fb, mode);
    if(res)
    {
        return NULL;
    }
    return __kfb_load_mode_info(fb);
}
int
kfb_unload_mode_info(struct kfb_framebuffer *fb, struct fb_mode_info *info)
{
    return __kfb_unload_mode_info(info);
}

int
kfb_get_current_mode(struct kfb_framebuffer *fb)
{
    int current_mode;
    kanawha_sys_seek(fb->mode_set_file, 0, SEEK_SET);
    char mode_strbuf[64];
    int total_read = 0;
    while(total_read < 64)
    {
        ssize_t read = kanawha_sys_read(fb->mode_set_file,
                                        mode_strbuf + total_read,
                                        64 - total_read);
        if(read < 0)
        {
            // Error
            return read;
        }
        total_read += read;
        if(read == 0)
        {
            break;
        }
    }
    mode_strbuf[total_read - 1] = '\0';
    current_mode = atoi(mode_strbuf);
    return current_mode;
}

int
kfb_set_current_mode(struct kfb_framebuffer *fb, int mode)
{
    int res;

    res = __kfb_set_mode_info(fb, mode);
    if(res)
    {
        return res;
    }

    struct fb_mode_info *info = __kfb_load_mode_info(fb);
    if(info == NULL)
    {
        return res;
    }

    // We should be able to switch modes now
    fb->have_buffer_data = 0;
    kanawha_sys_munmap(fb->buffer_data);
    fb->buffer_data = NULL;

    res = __kfb_set_mode(fb, mode);
    if(res)
    {
        // Uh-Oh
        // Try and remap the old one
        int mmap_res;
        mmap_res = kanawha_sys_mmap(
            fb->buffer_file,
            0,
            (void **)&fb->buffer_data,
            (fb->current_mode_info->buffer_size + 0xFFF) & ~0xFFF,
            MMAP_SHARED | MMAP_PROT_READ | MMAP_PROT_WRITE);
        if(mmap_res)
        {
            // shit shit shit shit shit shit
            abort();
        }
        else
        {
            fb->have_buffer_data = 1;
        }
        return res;
    }
    fb->current_mode_info = info;

    res = kanawha_sys_mmap(fb->buffer_file,
                           0,
                           (void **)&fb->buffer_data,
                           (info->buffer_size + 0xFFF) & ~0xFFF,
                           MMAP_SHARED | MMAP_PROT_READ | MMAP_PROT_WRITE);
    if(res)
    {
        // This mode has no buffer data? (or something else went wrong)
        // Fine...
        fb->have_buffer_data = 0;
        return 0;
    }

    fb->have_buffer_data = 1;

    return 0;
}

static inline int
__kfb_merge_rgba(uint32_t *into, uint32_t value, size_t merged_so_far)
{
    if(merged_so_far == 0)
    {
        *into = value;
        return 0;
    }

    return -1;
}

int
kfb_flush_framebuffer(struct kfb_framebuffer *buffer)
{
    return kanawha_sys_flush(buffer->buffer_file, 0);
}

int
kfb_blit_with_transform(void *to,
                        size_t to_width,
                        size_t to_height,
                        size_t to_offset_x,
                        size_t to_offset_y,
                        struct gfx_layout *to_layout,
                        void *from,
                        size_t from_width,
                        size_t from_height,
                        size_t from_offset_x,
                        size_t from_offset_y,
                        struct gfx_layout *from_layout,
                        void *xform_state,
                        kfb_rgba_t (*xform)(kfb_rgba_t color, void *state))
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
                res = paint_convert_pixel(
                        GFX_FORMAT_RGBA32,
                        &cur_rgba,
                        from_layout->format,
                        from_data);
                if(res)
                {
                    printf("kfb: Failed to convert to rgba!\n");
                    continue;
                }

                kfb_rgba_t to_xform = {
                    .r = (cur_rgba) & 0xFF,
                    .g = (cur_rgba >> 8) & 0xFF,
                    .b = (cur_rgba >> 16) & 0xFF,
                    .a = (cur_rgba >> 24) & 0xFF,
                };
                to_xform = (*xform)(to_xform, xform_state);
                cur_rgba = (uint32_t)to_xform.r |
                           (((uint32_t)to_xform.g & 0xFF) << 8) |
                           (((uint32_t)to_xform.b & 0xFF) << 16) |
                           (((uint32_t)to_xform.a & 0xFF) << 24);
                if(((cur_rgba >> 24) & 0xFF) > 0)
                {
                    res = paint_convert_pixel(
                            to_layout->format,
                            to_data,
                            GFX_FORMAT_RGBA32,
                            &cur_rgba);
                    if(res)
                    {
                        printf("kfb: Failed to convert from rgba!\n");
                    }
                }
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

int
kfb_blit(void *to,
         size_t to_width,
         size_t to_height,
         size_t to_offset_x,
         size_t to_offset_y,
         struct gfx_layout *to_layout,
         void *from,
         size_t from_width,
         size_t from_height,
         size_t from_offset_x,
         size_t from_offset_y,
         struct gfx_layout *from_layout)
{
    return kfb_blit_with_transform(to,
                                   to_width,
                                   to_height,
                                   to_offset_x,
                                   to_offset_y,
                                   to_layout,
                                   from,
                                   from_width,
                                   from_height,
                                   from_offset_x,
                                   from_offset_y,
                                   from_layout,
                                   NULL,
                                   NULL);
}

int
kfb_blit_image_with_transform(void *to,
                              size_t to_width,
                              size_t to_height,
                              size_t to_offset_x,
                              size_t to_offset_y,
                              struct gfx_layout *to_layout,
                              struct kfb_image *image,
                              void *xform_state,
                              kfb_rgba_t (*xform)(kfb_rgba_t color,
                                                  void *state))
{
    struct gfx_layout img_layout = {
        .format = image->format,
        .stride = image->stride,
        .offset = image->offset,
        .width = image->resx,
        .height = image->resx,
        .order = image->order,
    };
    return kfb_blit_with_transform(to,
                                   to_width,
                                   to_height,
                                   to_offset_x,
                                   to_offset_y,
                                   to_layout,
                                   image->data,
                                   image->resx,
                                   image->resy,
                                   0,
                                   0,
                                   &img_layout,
                                   xform_state,
                                   xform);
}

int
kfb_blit_image(void *to,
               size_t to_width,
               size_t to_height,
               size_t to_offset_x,
               size_t to_offset_y,
               struct gfx_layout *to_layout,
               struct kfb_image *image)
{
    return kfb_blit_image_with_transform(to,
                                         to_width,
                                         to_height,
                                         to_offset_x,
                                         to_offset_y,
                                         to_layout,
                                         image,
                                         NULL,
                                         NULL);
}

// static inline kfb_rgba_t
//__kfb_rgba_tint(kfb_rgba_t to_tint, void *tint_ptr)
//{
//     kfb_rgba_t tint = *(kfb_rgba_t *)tint_ptr;
//     if(to_tint.a == 0)
//     {
//         return to_tint;
//     }
//     if(tint.a == 0)
//     {
//         return to_tint;
//     }
//
//     uint16_t a_sum = to_tint.a + tint.a;
//     float tint_strength = (float)tint.a / (float)a_sum;
//
//     uint16_t r = (tint_strength * tint.r) + ((1.0 - tint_strength) *
//     to_tint.r); uint16_t g = (tint_strength * tint.g) + ((1.0 -
//     tint_strength) * to_tint.g); uint16_t b = (tint_strength * tint.b) +
//     ((1.0 - tint_strength) * to_tint.b);
//
//     if(r > 255)
//     {
//         r = 255;
//     }
//     if(g > 255)
//     {
//         g = 255;
//     }
//     if(b > 255)
//     {
//         b = 255;
//     }
//
//     to_tint.r = r;
//     to_tint.g = g;
//     to_tint.b = b;
//     return to_tint;
// }

static kfb_rgba_t
__kfb_brightness_as_color(kfb_rgba_t b_color, void *color_ptr)
{
    kfb_rgba_t color = *(kfb_rgba_t *)color_ptr;
    float b_color_br =
        ((float)b_color.r + (float)b_color.g + (float)b_color.b) /
        (3.0f * 255.0f);
    float mult = b_color_br;
    int16_t r = color.r * mult;
    int16_t g = color.g * mult;
    int16_t b = color.b * mult;
    if(r > 255)
    {
        r = 255;
    }
    if(g > 255)
    {
        g = 255;
    }
    if(b > 255)
    {
        b = 255;
    }
    kfb_rgba_t ret = {
        .r = r,
        .g = g,
        .b = b,
        .a = b_color.a,
    };
    return ret;
}

int
kfb_blit_image_brightness_as_color(void *to,
                                   size_t to_width,
                                   size_t to_height,
                                   size_t to_offset_x,
                                   size_t to_offset_y,
                                   struct gfx_layout *to_layout,
                                   struct kfb_image *image,
                                   kfb_rgba_t color)
{
    return kfb_blit_image_with_transform(to,
                                         to_width,
                                         to_height,
                                         to_offset_x,
                                         to_offset_y,
                                         to_layout,
                                         image,
                                         &color,
                                         __kfb_brightness_as_color);
}

int
kfb_framebuffer_copy_direct(struct kfb_framebuffer *fb,
                            size_t offset,
                            void *data,
                            size_t datalen)
{
    if(!fb->have_buffer_data)
    {
        return -EINVAL;
    }

    size_t room = fb->current_mode_info->buffer_size - offset;
    if(room < datalen)
    {
        return -EINVAL;
    }

    memcpy(fb->buffer_data + offset, data, datalen);

    return 0;
}
