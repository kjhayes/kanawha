
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>
#include <drivers/vga/vga.h>
#include <drivers/vga/fb.h>

extern struct vga_fb_mode vga_fb_mode_text_80_25;
extern struct vga_fb_mode vga_fb_mode_graphics_320_200;
extern struct vga_fb_mode vga_fb_mode_graphics_640_400;
extern struct vga_fb_mode vga_fb_mode_osdev_320_200;

static struct vga_fb_mode *vga_fb_modes[] = {
    &vga_fb_mode_text_80_25,
    &vga_fb_mode_graphics_320_200,
    &vga_fb_mode_graphics_640_400,
    &vga_fb_mode_osdev_320_200,
};
#define VGA_FB_NUM_MODES (sizeof(vga_fb_modes) / sizeof(*vga_fb_modes))

// Must be called with the mode lock held
static int
__vga_fb_set_buffer_size(
        struct vga_fb *fb,
        size_t size)
{
    int res;

    if(size == 0) {
        return -EINVAL;
    }

    order_t new_buffer_order = 64 - __builtin_clzl(size);
    void __phys *new_buffer;
    res = page_alloc(new_buffer_order, &new_buffer, 0);
    if(res) {
        return res;
    }

    if(fb->buffer_exists) {
        res = page_free(fb->buffer_order, fb->buffer);
        if(res) {
            page_free(new_buffer_order, new_buffer);
            return res;
        }
    }

    fb->buffer = new_buffer;
    fb->buffer_order = new_buffer_order;
    fb->buffer_exists = 1;

    // Clear the buffer
    memset_p(fb->buffer, 0, 1ULL<<fb->buffer_order);

    return 0;
}

#define VGA_FB_BASE_ADDR (void __phys *)0xA0000



static struct fb_mode_info *
vga_fb_get_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES) {
        return NULL;
    }

    return vga_fb_modes[index]->mode_info;
}

static int
vga_fb_put_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES) {
        return -EINVAL;
    }

    return 0;
}

static int
vga_fb_set_mode(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    if(index >= VGA_FB_NUM_MODES) {
        return -ENXIO;
    }

    int res;
    spin_lock(&fb->mode_lock);

    struct vga_fb_mode *mode = vga_fb_modes[index];

    res = __vga_fb_set_buffer_size(fb, mode->mode_info->buffer_size);
    if(res) {
        spin_unlock(&fb->mode_lock);
        return res;
    }

    res = (mode->setup)(fb);
    if(res) {
        spin_unlock(&fb->mode_lock);
        return res;
    }

    fb->current_mode = index;

    spin_unlock(&fb->mode_lock);
    return res;
}

static ssize_t
vga_fb_get_mode(
        struct fb_dev *dev)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    return fb->current_mode;
}

static int
vga_fb_load_buffer(
        struct fb_dev *dev,
        void __phys ** base_out)
{
    int res;
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    size_t buffer_size;

    spin_lock(&fb->mode_lock);

    DEBUG_ASSERT(fb->buffer_exists);

    *base_out = fb->buffer;

    spin_unlock(&fb->mode_lock);
    return 0;
}
static int
vga_fb_unload_buffer(
        struct fb_dev *dev,
        void __phys * base_out)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    int res;

    spin_lock(&fb->mode_lock);

    DEBUG_ASSERT(fb->buffer_exists);

    // Don't need to do anything, we allocate and deallocate the buffer on mode switch

    spin_unlock(&fb->mode_lock);

    return 0;
}

static int
vga_fb_flush_buffer(
        struct fb_dev *dev)
{
    int res;
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    spin_lock(&fb->mode_lock);

    if(!fb->buffer_exists) {
        spin_unlock(&fb->mode_lock);
        return 0;
    }

    if(fb->current_mode >= VGA_FB_NUM_MODES) {
        spin_unlock(&fb->mode_lock);
        return -EINVAL;
    }

    struct vga_fb_mode *mode = vga_fb_modes[fb->current_mode];

    res = (*mode->flush)(fb);

    spin_unlock(&fb->mode_lock);
    return res;
}

static struct fb_driver vga_fb_driver = {
    .set_mode = vga_fb_set_mode,
    .get_mode = vga_fb_get_mode,
    .get_mode_info = vga_fb_get_mode_info,
    .put_mode_info = vga_fb_put_mode_info,
    .load_buffer = vga_fb_load_buffer,
    .unload_buffer = vga_fb_unload_buffer,
    .flush_buffer = vga_fb_flush_buffer,
};

static int
register_vga_fb_dev(void)
{
    int res;

    struct vga_fb *fb = kzmalloc(sizeof(struct vga_fb), KM_KERNEL);
    if(fb == NULL) {
        return -ENOMEM;
    }

    res = vga_dev_init(&fb->vga_dev);
    if(res) {
        kfree(fb);
        return res;
    }

    spinlock_init(&fb->mode_lock);
    fb->buffer_exists = 0;
    fb->current_mode = 0;
    res = vga_fb_set_mode(&fb->fb_dev, 0);
    if(res) {
        kfree(fb);
        return res;
    }

    fb->fb_dev.driver = &vga_fb_driver;

    res = register_fb_dev(
            &fb->fb_dev,
            "vga");
    if(res) {
        printk("register_fb_dev returned %s\n",
                errnostr(res));
        kfree(fb);
        return res;
    }

    return 0;
}

declare_init_desc(device, register_vga_fb_dev, "Registering VGA Framebuffer Device");
