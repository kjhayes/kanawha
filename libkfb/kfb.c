
#include <kanawha/kfb.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/fb.h>
#include <kanawha/file.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int
__kfb_set_mode_info(
        struct kfb_framebuffer *fb,
        int mode)
{
    char strbuf[64];
    snprintf(strbuf, 64, "%d", mode);
    strbuf[64-1] = '\0';

    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);

    size_t len = strlen(strbuf);

    ssize_t total_written = 0;
    while(total_written < len) {
        ssize_t written = kanawha_sys_write(
                fb->mode_info_file,
                strbuf + total_written,
                len - total_written);
        if(written < 0) {
            // Error
            return written;
        }
        total_written += written;
        if(written == 0) {
            break;
        }
    }
    kanawha_sys_flush(fb->mode_info_file, 0);
    return 0;
}

static int
__kfb_set_mode(
        struct kfb_framebuffer *fb,
        int mode)
{
    char strbuf[64];
    snprintf(strbuf, 64, "%d", mode);
    strbuf[64-1] = '\0';

    kanawha_sys_seek(fb->mode_set_file, 0, SEEK_SET);

    size_t len = strlen(strbuf);

    ssize_t total_written = 0;
    while(total_written < len) {
        ssize_t written = kanawha_sys_write(
                fb->mode_set_file,
                strbuf + total_written,
                len - total_written);
        if(written < 0) {
            // Error
            return written;
        }
        total_written += written;
        if(written == 0) {
            break;
        }
    }
    kanawha_sys_flush(fb->mode_set_file, 0);
    return 0;
}

static struct fb_mode_info *
__kfb_load_mode_info(
        struct kfb_framebuffer *fb)
{
    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);
    size_t size = kanawha_sys_seek(fb->mode_info_file, 0, SEEK_END);

    if(size == 0) {
        // Mode does not exist
        return NULL;
    }

    struct fb_mode_info *info = malloc(size);
    if(info == NULL) {
        return NULL;
    }
    memset(info, 0, size);

    kanawha_sys_seek(fb->mode_info_file, 0, SEEK_SET);

    size_t total_read = 0;
    while(total_read < size) {
        ssize_t read = kanawha_sys_read(fb->mode_info_file, info, size);
        if(read < 0) {
            free(info);
            return NULL;
        }
        total_read += read;
        if(read == 0) {
            break;
        }
    }

    return info;
}

static int
__kfb_unload_mode_info(
        struct fb_mode_info *info)
{
    free(info);
    return 0;
}

struct kfb_framebuffer *
kfb_load_framebuffer(
        const char *path)
{
    int res;

    fd_t buffer_file;
    fd_t mode_set_file;
    fd_t mode_info_file;

#ifdef PATHBUFLEN
#undef PATHBUFLEN
#endif
#define PATHBUFLEN 128
    char path_buf[PATHBUFLEN];

    snprintf(path_buf, PATHBUFLEN, "%s", path);
    path_buf[PATHBUFLEN-1] = '\0';
    res = kanawha_sys_open(
            path_buf,
            FILE_PERM_READ|FILE_PERM_WRITE,
            0,
            &buffer_file);
    if(res) {
        return NULL;
    }

    snprintf(path_buf, PATHBUFLEN, "%s/mode", path);
    path_buf[PATHBUFLEN-1] = '\0';
    res = kanawha_sys_open(
            path_buf,
            FILE_PERM_READ|FILE_PERM_WRITE,
            0,
            &mode_set_file);
    if(res) {
        kanawha_sys_close(buffer_file);
        return NULL;
    }

    snprintf(path_buf, PATHBUFLEN, "%s/info", path);
    path_buf[PATHBUFLEN-1] = '\0';
    res = kanawha_sys_open(
            path_buf,
            FILE_PERM_READ|FILE_PERM_WRITE,
            0,
            &mode_info_file);
    if(res) {
        kanawha_sys_close(buffer_file);
        kanawha_sys_close(mode_set_file);
        return NULL;
    }
#undef PATHBUFLEN

    struct kfb_framebuffer *fb =
        malloc(sizeof(struct kfb_framebuffer));
    if(fb == NULL) {
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
    if(current_mode < 0) {
        kanawha_sys_close(fb->buffer_file);
        kanawha_sys_close(fb->mode_set_file);
        kanawha_sys_close(fb->mode_info_file);
        free(fb);
        return NULL;
    }

    __kfb_set_mode_info(fb, current_mode);
    struct fb_mode_info *info = __kfb_load_mode_info(fb);
    if(info == NULL) {
        kanawha_sys_close(fb->buffer_file);
        kanawha_sys_close(fb->mode_set_file);
        kanawha_sys_close(fb->mode_info_file);
        free(fb);
        return NULL;
    }

    fb->current_mode_info = info;

    res = kanawha_sys_mmap(
            fb->buffer_file,
            0,
            (void**)&fb->buffer_data,
            (info->buffer_size + 0xFFF) & ~0xFFF,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        fb->have_buffer_data = 0;
    } else {
        fb->have_buffer_data = 1;
    }

    return fb;
}

int
kfb_unload_framebuffer(
        struct kfb_framebuffer *fb)
{
    kanawha_sys_close(fb->buffer_file);
    kanawha_sys_close(fb->mode_set_file);
    kanawha_sys_close(fb->mode_info_file);
    if(fb->current_mode_info != NULL) {
        __kfb_unload_mode_info(fb->current_mode_info);
    }
    if(fb->buffer_data != NULL) {
        kanawha_sys_munmap(fb->buffer_data);
    }
    free(fb);
    return 0;
}

struct fb_mode_info *
kfb_load_mode_info(
        struct kfb_framebuffer *fb,
        int mode)
{
    int res;
    res = __kfb_set_mode_info(fb, mode);
    if(res) {
        return NULL;
    }
    return __kfb_load_mode_info(fb);
}
int
kfb_unload_mode_info(
        struct kfb_framebuffer *fb,
        struct fb_mode_info *info)
{
    return __kfb_unload_mode_info(info);
}

int
kfb_get_current_mode(
        struct kfb_framebuffer *fb)
{
    int current_mode;
    kanawha_sys_seek(fb->mode_set_file, 0, SEEK_SET);
    char mode_strbuf[64];
    int total_read = 0;
    while(total_read < 64) {
        ssize_t read = kanawha_sys_read(
                fb->mode_set_file,
                mode_strbuf + total_read,
                64 - total_read);
        if(read < 0) {
            // Error
            return read;
        }
        total_read += read;
        if(read == 0) {
            break;
        }
    }
    mode_strbuf[total_read-1] = '\0';
    current_mode = atoi(mode_strbuf);
    return current_mode;
}

int
kfb_set_current_mode(
        struct kfb_framebuffer *fb,
        int mode)
{
    int res;

    res = __kfb_set_mode_info(fb, mode);
    if(res) {
        return res;
    }

    struct fb_mode_info *info = __kfb_load_mode_info(fb);
    if(info == NULL) {
        return res;
    }

    // We should be able to switch modes now
    fb->have_buffer_data = 0;
    kanawha_sys_munmap(fb->buffer_data);
    fb->buffer_data = NULL;

    res = __kfb_set_mode(fb, mode);
    if(res) {
        // Uh-Oh
        // Try and remap the old one
        int mmap_res;
        mmap_res = kanawha_sys_mmap(
            fb->buffer_file,
            0,
            (void**)&fb->buffer_data,
            (fb->current_mode_info->buffer_size + 0xFFF) & ~0xFFF,
            MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
        if(mmap_res) {
            // shit shit shit shit shit shit
            abort();
        } else {
            fb->have_buffer_data = 1;
        }
        return res;
    }
    fb->current_mode_info = info;

    res = kanawha_sys_mmap(
        fb->buffer_file,
        0,
        (void**)&fb->buffer_data,
        (info->buffer_size + 0xFFF) & ~0xFFF,
        MMAP_SHARED|MMAP_PROT_READ|MMAP_PROT_WRITE);
    if(res) {
        // This mode has no buffer data? (or something else went wrong)
        // Fine...
        fb->have_buffer_data = 0;
        return 0;
    }

    fb->have_buffer_data = 1;

    return 0;
}

// Use FB_FORMAT_RGBA as a "lingua franca"
static inline int
__kfb_convert_to_rgba(
        unsigned long format,
        void *data,
        uint8_t *rgba_out)
{
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
    uint8_t a = 0;
    switch(format) {
        case FB_LAYER_FORMAT_RGBA32:
            *(uint32_t*)rgba_out = *(uint32_t*)data;
            return 0;
        case FB_LAYER_FORMAT_RBGA32:
            r = ((uint8_t*)data)[0];
            b = ((uint8_t*)data)[1];
            g = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case FB_LAYER_FORMAT_BRGA32:
            b = ((uint8_t*)data)[0];
            r = ((uint8_t*)data)[1];
            g = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case FB_LAYER_FORMAT_BGRA32:
            b = ((uint8_t*)data)[0];
            g = ((uint8_t*)data)[1];
            r = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case FB_LAYER_FORMAT_GBRA32:
            g = ((uint8_t*)data)[0];
            b = ((uint8_t*)data)[1];
            r = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        case FB_LAYER_FORMAT_GRBA32:
            g = ((uint8_t*)data)[0];
            r = ((uint8_t*)data)[1];
            b = ((uint8_t*)data)[2];
            a = ((uint8_t*)data)[3];
            break;
        default:
            return -EINVAL;
    }

    *(uint32_t*)rgba_out = r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);

    return 0;
}

static inline int
__kfb_convert_from_rgba(
        uint32_t *rgba,
        unsigned long to_format,
        void *to_data)
{
    uint8_t *rgba_bytes = (uint8_t*)rgba;
    uint32_t r = rgba_bytes[0];
    uint32_t g = rgba_bytes[1];
    uint32_t b = rgba_bytes[2];
    uint32_t a = rgba_bytes[3];

    switch(to_format) {
        case FB_LAYER_FORMAT_RGBA32:
            *(uint32_t*)to_data = *(uint32_t*)rgba;
            return 0;
        case FB_LAYER_FORMAT_RBGA32:
            *(uint32_t*)to_data = r | (b<<8) | (g<<16) | (a<<24);
            return 0;
        case FB_LAYER_FORMAT_BRGA32:
            *(uint32_t*)to_data = b | (r<<8) | (g<<16) | (a<<24);
            return 0;
        case FB_LAYER_FORMAT_BGRA32:
            *(uint32_t*)to_data = b | (g<<8) | (r<<16) | (a<<24);
            return 0;
        case FB_LAYER_FORMAT_GBRA32:
            *(uint32_t*)to_data = g | (b<<8) | (r<<16) | (a<<24);
            return 0;
        case FB_LAYER_FORMAT_GRBA32:
            *(uint32_t*)to_data = g | (r<<8) | (b<<16) | (a<<24);
            return 0;
        case FB_LAYER_FORMAT_MONO8:
            *(uint8_t*)to_data = (r + b + g)/3;
            return 0;
        case FB_LAYER_FORMAT_MONO16:
            *(uint16_t*)to_data = ((r + b + g)/3) << 8;
            return 0;
        case FB_LAYER_FORMAT_MONO32:
            *(uint32_t*)to_data = ((r + b + g)/3) << 24;
            return 0;
        case FB_LAYER_FORMAT_MONO64:
            *(uint64_t*)to_data = (uint64_t)((r + b + g)/3) << 56;
            return 0;
        case FB_LAYER_FORMAT_VGA_CHAR:
        case FB_LAYER_FORMAT_ASCII:
            *(uint8_t*)to_data = ' ';
            return 0;
        default:
            break;
    }

    uint8_t avg = (r + b + g)/3;
    switch(to_format) {
        case FB_LAYER_FORMAT_BYTE_R1G1B1I1:
            *(uint8_t*)to_data =
                   (r >= 0x60)
                | ((g >= 0x60)<<1)
                | ((b >= 0x60)<<2)
                | ((avg >= 0x80)<<3);
            return 0;
        case FB_LAYER_FORMAT_BYTE_R3G3B2:
            *(uint8_t*)to_data =
                    (((r >> 5) & 0b111) << 0)
                  | (((g >> 5) & 0b111) << 3)
                  | (((b >> 6) & 0b011) << 6);
            return 0;
        case FB_LAYER_FORMAT_VGA_ATTR:
            *(uint8_t*)to_data =
                  ((r >= 0x60)
                | ((g >= 0x60)<<1)
                | ((b >= 0x60)<<2)
                | ((avg >= 0x80)<<3)) << 4;
            return 0;
        default:
            break;
    }

    return -EINVAL;
}

static inline int
__kfb_convert_pixel(
        unsigned long from_format,
        void *from_data,
        unsigned long to_format,
        void *to_data)
{
    uint32_t rgba;

    int res = __kfb_convert_to_rgba(
            from_format,
            from_data,
            (uint8_t*)&rgba);
    if(res) {
        return res;
    }
    //printf("rgba=0x%x\n",rgba);
    res = __kfb_convert_from_rgba(
            &rgba,
            to_format,
            to_data);
    if(res) {
        return res;
    }
    return 0;
}

static inline int
__kfb_merge_rgba(
        uint32_t *into,
        uint32_t value,
        size_t merged_so_far)
{
    if(merged_so_far == 0) {
        *into = value;
        return 0;
    }

    return -1;
}

int
kfb_flush_framebuffer(
        struct kfb_framebuffer *buffer)
{
    return kanawha_sys_flush(buffer->buffer_file, 0);
}


static inline int
kfb_blit_image_with_transform_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height,
        void *xform_state,
        kfb_rgba_t(*xform)(kfb_rgba_t color, void *state))
{
    if(layer >= fb->current_mode_info->layer_count) {
        fprintf(stderr, "Layer %d does not exists!\n", layer);
        return -EINVAL;
    }

    struct fb_layer_info *layer_info = &fb->current_mode_info->layer_infos[layer];

    // Clipping
    if(offset_x >= layer_info->width) {
        return 0;
    }
    if(offset_y >= layer_info->height) {
        return 0;
    }

    if(image->resx == 0 || image->resy == 0) {
        return -EINVAL;
    }
    if(width == 0 || height == 0) {
        return -EINVAL;
    }

    double px_step = 1.0 / (double)width;
    double py_step = 1.0 / (double)height;

    if(px_step <= 0.0 || py_step <= 0.0) {
        return -EINVAL;
    }

#undef FROM_OFFSET
#define FROM_OFFSET(__px,__py) \
    image->offset + \
    (((size_t)(__px * image->resx))*image->stride) + \
    (((size_t)(__py * image->resy))*image->stride*image->resx)

#undef TO_OFFSET
#define TO_OFFSET(__x, __y) \
    layer_info->offset + \
    (((size_t)(__x))*layer_info->stride) + \
    (((size_t)(__y))*layer_info->stride*layer_info->width)

    for(size_t y = 0; y < height; y++) {
      for(size_t x = 0; x < width; x++) {

          uint32_t cur_rgba = 0;

          double px = (double)x / (double)width;
          double py = (double)y / (double)height;

          size_t from_offset = FROM_OFFSET(px, py);
          if((from_offset + layer_info->stride) > image->data_size) {
              continue;
          }
          uint8_t *from_data = &image->data[from_offset];

          int res = __kfb_convert_to_rgba(
              image->format,
              from_data,
              (uint8_t*)&cur_rgba);
          if(res) {
              continue;
          }

          if(xform) {
              kfb_rgba_t to_xform = {
                  .r = (cur_rgba) & 0xFF,
                  .g = (cur_rgba>>8) & 0xFF,
                  .b = (cur_rgba>>16) & 0xFF,
                  .a = (cur_rgba>>24) & 0xFF,
              };
              to_xform = (*xform)(to_xform, xform_state);
              cur_rgba =
                  (uint32_t)to_xform.r |
                  (((uint32_t)to_xform.g&0xFF)<<8) |
                  (((uint32_t)to_xform.b&0xFF)<<16) |
                  (((uint32_t)to_xform.a&0xFF)<<24);
          }
         
          if(((cur_rgba>>24)&0xFF) > 0) {
              size_t to_offset = TO_OFFSET(offset_x + x, offset_y + y);
              if(offset_x + x >= layer_info->width) {
                  break;
              }
              if(offset_y + y >= layer_info->height) {
                  break;
              }
              if(to_offset >= fb->current_mode_info->buffer_size) {
                  continue;
              }
              int res = __kfb_convert_from_rgba(
                  &cur_rgba,
                  layer_info->format,
                  &fb->buffer_data[to_offset]);
          }
      }
    }

    return 0;
}

int
kfb_blit_image_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height)
{
    return kfb_blit_image_with_transform_onto_layer(
            fb,
            layer,
            image,
            offset_x,
            offset_y,
            width,
            height,
            NULL,
            NULL);
}

static inline kfb_rgba_t
__kfb_rgba_tint(
        kfb_rgba_t to_tint,
        void *tint_ptr)
{
    kfb_rgba_t tint = *(kfb_rgba_t*)tint_ptr;
    if(to_tint.a == 0) {
        return to_tint;
    }
    if(tint.a == 0) {
        return to_tint;
    }

    uint16_t a_sum = to_tint.a + tint.a;
    float tint_strength = (float)tint.a / (float)a_sum;
    
    uint16_t r = (tint_strength * tint.r) + ((1.0 - tint_strength) * to_tint.r);
    uint16_t g = (tint_strength * tint.g) + ((1.0 - tint_strength) * to_tint.g);
    uint16_t b = (tint_strength * tint.b) + ((1.0 - tint_strength) * to_tint.b);

    if(r > 255) { r = 255; }
    if(g > 255) { g = 255; }
    if(b > 255) { b = 255; }

    to_tint.r = r;
    to_tint.g = g;
    to_tint.b = b;
    return to_tint;
}

int
kfb_blit_image_with_tint_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height,
        kfb_rgba_t tint)
{
    return kfb_blit_image_with_transform_onto_layer(
            fb,
            layer,
            image,
            offset_x,
            offset_y,
            width,
            height,
            &tint,
            __kfb_rgba_tint);
}
static kfb_rgba_t
__kfb_brightness_as_color(
        kfb_rgba_t b_color,
        void *color_ptr)
{
    kfb_rgba_t color = *(kfb_rgba_t*)color_ptr;
    float b_color_br = ((float)b_color.r + (float)b_color.g + (float)b_color.b)/(3.0f * 255.0f);
    float mult = b_color_br;
    int16_t r = color.r * mult;
    int16_t g = color.g * mult;
    int16_t b = color.b * mult;
    if(r > 255) {r = 255;}
    if(g > 255) {g = 255;}
    if(b > 255) {b = 255;}
    kfb_rgba_t ret = {
        .r = r,
        .g = g,
        .b = b,
        .a = b_color.a,
    };
    return ret;
}

int
kfb_blit_image_brightness_as_color_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height,
        kfb_rgba_t color)
{
    return kfb_blit_image_with_transform_onto_layer(
            fb,
            layer,
            image,
            offset_x,
            offset_y,
            width,
            height,
            &color,
            __kfb_brightness_as_color);
}

