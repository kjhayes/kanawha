
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
        uint8_t *rgba,
        unsigned long to_format,
        void *to_data)
{
    uint32_t r = rgba[0];
    uint32_t g = rgba[1];
    uint32_t b = rgba[2];
    uint32_t a = rgba[3];

    switch(to_format) {
        case FB_LAYER_FORMAT_RGBA32:
            *(uint32_t*)to_data = *rgba;
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
                    ((r >> 5) & 0x07)
                  | ((g >> 2) & 0x38)
                  | ((b >> 0) & 0xC0);
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
            (uint8_t*)&rgba,
            to_format,
            to_data);
    if(res) {
        return res;
    }
    return 0;
}

int
kfb_flush_framebuffer(
        struct kfb_framebuffer *buffer)
{
    return kanawha_sys_flush(buffer->buffer_file, 0);
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
    if(layer >= fb->current_mode_info->layer_count) {
        fprintf(stderr, "Layer %d does not exists!\n", layer);
        return -EINVAL;
    }

    struct fb_layer_info *layer_info = &fb->current_mode_info->layer_infos[layer];

    if(offset_x >= layer_info->width) {
        return 0;
    }
    if(offset_y >= layer_info->height) {
        return 0;
    }
    if(offset_x + width > layer_info->width) {
        width = layer_info->width - offset_x;
    }
    if(offset_y + height > layer_info->height) {
        height = layer_info->height - offset_y;
    }

    size_t image_scaler_x = 1;
    size_t image_divisor_x = 1;
    size_t image_scaler_y = 1;
    size_t image_divisor_y = 1;

    size_t end_x = image->resx;
    size_t end_y = image->resy;

    image_scaler_x = image->resx;
    image_divisor_x = width;
    image_scaler_y = image->resy;
    image_divisor_y = height;

    if(layer_info->order != FB_LAYER_ORDER_ROW_MAJOR ||
       image->order != FB_LAYER_ORDER_ROW_MAJOR) {
        // We're going to assume both are row major for now
        return -EUNIMPL;
    }

    for(size_t iy = 0; iy < end_y; iy++)
    {
    
      size_t image_y = (iy * (image_scaler_y))/image_divisor_y; 
      size_t layer_y = iy + offset_y;

      if(image_y >= image->resy) {continue;}

      size_t next_image_y = ((iy+1) * (image_scaler_y))/image_divisor_y; 
      if(next_image_y > end_y+1) {
          next_image_y = end_y+1;
      }

      for(size_t ix = 0; ix < end_x; ix++) {

          size_t image_x = (ix * (image_scaler_x))/image_divisor_x;
          size_t layer_x = ix + offset_x;

          size_t next_image_x = ((ix+1) * (image_scaler_x))/image_divisor_x;
          if(next_image_x > end_x+1) {
              next_image_x = end_x+1;
          }

          if(image_x >= image->resx) {break;}

          size_t sample_x = next_image_x - image_x;
          size_t sample_y = next_image_y - image_y;

#define FROM_OFFSET(__x,__y) image->offset + ((image_x + __x)*image->stride) + ((image_y + __y)*image->stride*image->resx)

#define TO_OFFSET(__x, __y) layer_info->offset + ((layer_x + __x)*layer_info->stride) + ((layer_y + __y)*layer_info->stride*layer_info->width)

          uint8_t *to_data = &fb->buffer_data[TO_OFFSET(0,0)];
          if(sample_x <= 1 && sample_y <= 1) {
              uint8_t *from_data = &image->data[FROM_OFFSET(0,0)];

              int res = __kfb_convert_pixel(
                      image->format,
                      from_data,
                      layer_info->format,
                      to_data);
              if(res) {
                  return res;
              }
          } else {
              int res;
              uint32_t rgba[sample_x * sample_y];
              for(size_t sy = 0; sy < sample_y; sy++) {
                  for(size_t sx = 0; sx < sample_x; sx++) {
                      res = __kfb_convert_to_rgba(
                          image->format,
                          &image->data[FROM_OFFSET(sx,sy)],
                          (uint8_t*)&rgba[sx + (sample_x * sy)]);
                      if(res) {
                          return res;
                      }
                  }
              }
              uint32_t r = 0;
              uint32_t g = 0;
              uint32_t b = 0;
              uint32_t a = 0;
              for(size_t index = 0; index < sample_x*sample_y; index++) {
                  uint8_t *data = (uint8_t*)&rgba[index];
                  r += data[0];
                  g += data[1];
                  b += data[2];
                  a += data[3];
              }
              r /= sample_x * sample_y;
              g /= sample_x * sample_y;
              b /= sample_x * sample_y;
              a /= sample_x * sample_y;
              uint32_t sampled_rgba = r | ((g&0xFF)<<8) | ((b&0xFF)<<16) | ((a&0xFF)<<24);
              res = __kfb_convert_from_rgba(
                      (uint8_t*)&sampled_rgba,
                      layer_info->format,
                      to_data);
              if(res) {
                  return res;
              }
          }
      }
    }

    return 0;
}

