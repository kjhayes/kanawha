#ifndef __ELK_KANAWHA__FB_HELPERS_H__
#define __ELK_KANAWHA__FB_HELPERS_H__

#include <kanawha/fb.h>
#include <kanawha/file.h>
#include <stddef.h>
#include <stdint.h>

typedef struct kfb_rgba
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} kfb_rgba_t;

struct kfb_framebuffer
{
    fd_t buffer_file;
    fd_t mode_set_file;
    fd_t mode_info_file;

    struct fb_mode_info *current_mode_info;
    int have_buffer_data;
    uint8_t *buffer_data;
};

struct kfb_framebuffer *
kfb_open_framebuffer(const char *path);
int
kfb_close_framebuffer(struct kfb_framebuffer *buffer);

struct kfb_framebuffer *
kfb_attach_framebuffer(fd_t file);
int
kfb_deattach_framebuffer(struct kfb_framebuffer *buffer);

struct fb_mode_info *
kfb_load_mode_info(struct kfb_framebuffer *buffer, int mode);
int
kfb_unload_mode_info(struct kfb_framebuffer *buffer, struct fb_mode_info *info);

int
kfb_get_current_mode(struct kfb_framebuffer *buffer);

int
kfb_set_current_mode(struct kfb_framebuffer *buffer, int mode);

static inline int
kfb_get_dimensions(
        struct kfb_framebuffer *fb,
        unsigned long *width,
        unsigned long *height)
{
    int current_mode = kfb_get_current_mode(fb);
    struct fb_mode_info *minfo = kfb_load_mode_info(fb, current_mode);
    *width = minfo->layer_infos[0].layout.width;
    *height = minfo->layer_infos[0].layout.height;
    kfb_unload_mode_info(fb, minfo);
    return 0;
}

int
kfb_flush_framebuffer(struct kfb_framebuffer *buffer);

struct kfb_image
{
    unsigned long format;
    unsigned long order;
    size_t stride;
    size_t offset;
    size_t resx;
    size_t resy;
    size_t data_size;
    uint8_t *data;
};

int
kfb_blit(void *to,
         size_t to_width,
         size_t to_height,
         size_t to_off_x,
         size_t to_off_y,
         struct gfx_layout *to_layout,
         void *from,
         size_t from_width,
         size_t from_height,
         size_t from_off_x,
         size_t from_off_y,
         struct gfx_layout *from_layout
         );

int
kfb_blit_with_transform(
         void *to,
         size_t to_width,
         size_t to_height,
         size_t to_off_x,
         size_t to_off_y,
         struct gfx_layout *to_layout,
         void *from,
         size_t from_width,
         size_t from_height,
         size_t from_off_x,
         size_t from_off_y,
         struct gfx_layout *from_layout,
         void *xform_state,
         kfb_rgba_t (*xform)(kfb_rgba_t color,void *state)
         );

int
kfb_blit_image_with_transform(
        void *to,
        size_t to_width,
        size_t to_height,
        size_t to_offset_x,
        size_t to_offset_y,
        struct gfx_layout *to_layout,
        struct kfb_image *image,
        void *xform_state,
        kfb_rgba_t (*xform)(kfb_rgba_t color,void *state)
        );

int
kfb_blit_image(
        void *to,
        size_t to_width,
        size_t to_height,
        size_t to_offset_x,
        size_t to_offset_y,
        struct gfx_layout *to_layout,
        struct kfb_image *image
        );

int
kfb_blit_image_brightness_as_color(
        void *to,
        size_t to_width,
        size_t to_height,
        size_t to_offset_x,
        size_t to_offset_y,
        struct gfx_layout *to_layout,
        struct kfb_image *image,
        kfb_rgba_t color
        );

int
kfb_framebuffer_copy_direct(struct kfb_framebuffer *fb,
                            size_t offset,
                            void *data,
                            size_t datalen);

#endif
