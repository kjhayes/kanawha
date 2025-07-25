
#include <drivers/vga/vga.h>
#include <drivers/vga/fb.h>
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>

struct vga_fb;

static int
vga_fb_flush_mode_text_80_25(
        struct vga_fb *fb)
{
    void *vga_mem = __va((void __phys *)0xA0000);
    void *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    memcpy(vga_mem, buffer, 80*25*2);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_setup_mode_text_80_25(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    vga_screen_disable(vga);

//    vga_write_field(vga, WriteMode, 0);
//    vga_set_write_planes(vga, 0b1111);
//    vga_write_field(vga, ReadMode, 0);
//    vga_write_field(vga, AlphanumericModeDisable, 0);
//    vga_set_horizontal_panning(vga, 8);

    // TODO: Load a font

    vga_screen_enable(vga);

    res = vga_fb_flush_mode_text_80_25(fb);
    if(res) {
        wprintk("Failed to flush VGA framebuffer after mode-setting (err=%s)!\n",
                errnostr(res));
    }

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = 80*25*2,
    .layer_count = 2,
    .layer_infos = {
        {
            .format = FB_LAYER_FORMAT_VGA_CHAR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 0,
            .stride = 2,
        },
        {
            .format = FB_LAYER_FORMAT_VGA_ATTR,
            .order = FB_LAYER_ORDER_ROW_MAJOR,
            .width = 80,
            .height = 25,
            .offset = 0,
            .stride = 2,
        },
    },
};

struct vga_fb_mode 
vga_fb_mode_text_80_25 = {
    .flush = vga_fb_flush_mode_text_80_25,
    .setup = vga_fb_setup_mode_text_80_25,
    .mode_info = &mode_info,
};

