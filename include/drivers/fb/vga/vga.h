#ifndef __KANAWHA__VGA_FB_H__
#define __KANAWHA__VGA_FB_H__

#include <drivers/vga/vga.h>
#include <kanawha/dev/fb.h>
#include <kanawha/lock.h>

struct vga_fb;

struct vga_fb_mode
{
    int (*flush)(struct vga_fb *);
    int (*setup)(struct vga_fb *);

    struct fb_mode_info *mode_info;
};

struct vga_fb
{
    struct fb_dev fb_dev;
    struct vga_dev *vga_dev;

    thread_lock_t mode_lock;
    size_t current_mode;
    int buffer_exists;
    void __phys *buffer;
    order_t buffer_order;
};

#endif
