
#include <kanawha/fb_dev.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct vga_fb
{
    struct fb_dev fb_dev;
    size_t current_mode;
};

static struct fb_mode_info vga_text_mode_0 =
{
    .buffer_size = 80 * 25 * 2,
    .layer_count = 2,
    .layer_infos = {
        {
            .format = FB_LAYER_FORMAT_VGA_CHAR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 0,
            .stride = 1,
        },
        {
            .format = FB_LAYER_FORMAT_VGA_ATTR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 1,
            .stride = 1,
        },
    },
};

static struct fb_mode_info *
vga_fb_get_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(index) {
        case 0:
            return &vga_text_mode_0;
        default:
            return NULL;
    }
}
static int
vga_fb_put_mode_info(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(index) {
        case 0:
            return 0;
        default:
            return -EINVAL;
    }
}
static int
vga_fb_set_mode(
        struct fb_dev *dev,
        size_t index)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    if(index == 0) {
        fb->current_mode = 0;
        return 0;
    } else {
        return -EINVAL;
    }
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
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(fb->current_mode) {
        case 0:
            *base_out = (void __phys *)0xB8000;
            return 0;
        default:
            return -EINVAL;
    }
}
static int
vga_fb_unload_buffer(
        struct fb_dev *dev,
        void __phys * base_out)
{
    struct vga_fb *fb =
        container_of(dev, struct vga_fb, fb_dev);

    switch(fb->current_mode) {
        case 0:
            DEBUG_ASSERT(base_out == (void __phys *)0xB8000);
            return 0;
        default:
            return -EINVAL;
    }
}

static int
vga_fb_flush_buffer(
        struct fb_dev *dev)
{
    return 0;
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

    struct vga_fb *fb = kmalloc(sizeof(struct vga_fb));
    if(fb == NULL) {
        return -ENOMEM;
    }
    memset(fb, 0, sizeof(struct vga_fb));

    fb->current_mode = 0;

    res = register_fb_dev(
            &fb->fb_dev,
            "vga",
            &vga_fb_driver);
    if(res) {
        printk("register_fb_dev returned %s\n",
                errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(device, register_vga_fb_dev, "Registering VGA Framebuffer Device");
