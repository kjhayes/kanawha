#ifndef __ELK_KANAWHA__FB_HELPERS_H__
#define __ELK_KANAWHA__FB_HELPERS_H__

#include <stdint.h>
#include <stddef.h>
#include <kanawha/fb.h>
#include <kanawha/file.h>

typedef struct kfb_rgba {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} kfb_rgba_t;

struct kfb_framebuffer {
    fd_t buffer_file;
    fd_t mode_set_file;
    fd_t mode_info_file;

    struct fb_mode_info *current_mode_info;
    int have_buffer_data;
    uint8_t *buffer_data;
};

struct kfb_framebuffer *
kfb_load_framebuffer(
        const char *path);
int
kfb_unload_framebuffer(
        struct kfb_framebuffer *buffer);

struct fb_mode_info *
kfb_load_mode_info(
        struct kfb_framebuffer *buffer,
        int mode);
int
kfb_unload_mode_info(
        struct kfb_framebuffer *buffer,
        struct fb_mode_info *info);

int
kfb_get_current_mode(
        struct kfb_framebuffer *buffer);

int
kfb_set_current_mode(
        struct kfb_framebuffer *buffer,
        int mode);

int
kfb_flush_framebuffer(
        struct kfb_framebuffer *buffer);

struct kfb_image {
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
kfb_blit_image_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height
        );

int
kfb_blit_image_with_tint_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height,
        kfb_rgba_t tint);

int
kfb_blit_image_brightness_as_color_onto_layer(
        struct kfb_framebuffer *fb,
        size_t layer,
        struct kfb_image *image,
        size_t offset_x,
        size_t offset_y,
        size_t width,
        size_t height,
        kfb_rgba_t color);

int
kfb_framebuffer_copy_direct(
	struct kfb_framebuffer *fb,
	size_t offset,
	void *data,
	size_t datalen);

#endif
