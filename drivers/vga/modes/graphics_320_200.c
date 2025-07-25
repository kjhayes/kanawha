
#include <drivers/vga/vga.h>
#include <drivers/vga/fb.h>
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>

static int
vga_fb_flush_mode_graphics_320_200(
        struct vga_fb *fb)
{
    void *vga_mem = __va((void __phys *)0xA0000);
    void *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    memcpy(vga_mem, buffer, 320 * 200);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_setup_mode_graphics_320_200(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    vga_screen_disable(vga);

    vga_enable_linear(vga);
    vga_disable_even_odd(vga);
    vga_write_field(vga, WriteMode, 0);
    vga_set_write_planes(vga, 0b1111);
    vga_set_color_planes(vga, 0b1111);
    vga_write_field(vga, ReadMode, 0);
    vga_write_field(vga, AlphanumericModeDisable, 1);
    vga_set_color_mode_pop_4(vga);
    vga_enable_8_bit_color(vga);
    vga_set_horizontal_panning(vga, 0);
    vga_disable_half_rate_dot_clock(vga);
    vga_enable_8_dot_mode(vga);

    vga_unlock_crt_reg(vga);

    vga_crt_disable_retrace(vga);

    // Because we are using 256 color mode, we need to double the "horizontal resolution" our timings are targeting
    static const uint16_t effective_hres = 320;
    static const uint16_t effective_vres = 200;
    static const uint16_t hblank = 32;
    static const uint16_t vblank = 32;
    vga_crt_set_horizontal_total(vga, ((effective_hres + hblank) * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_total(vga, (effective_vres + vblank));

    vga_crt_set_horizontal_display_end(vga, (effective_hres * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_display_end(vga, effective_vres);

    vga_crt_set_horizontal_blanking_start(vga, (effective_hres * 2) / vga_get_dots_per_character(vga));
    vga_crt_set_horizontal_blanking_end(vga, (hblank * 2) / vga_get_dots_per_character(vga));

    vga_crt_set_vertical_blanking_start(vga, effective_vres);
    vga_crt_set_vertical_blanking_end(vga, vblank);
   
    vga_crt_disable_scan_doubling(vga);
    vga_crt_set_maximum_scanline(vga, 0);
    vga_crt_set_address_size(vga, 4);
    vga_crt_set_scanline_offset(
            vga,
            (320*2)/8 // "address" length of a scanline
            );
    vga_lock_crt_reg(vga);

    // TODO Remove this (it's just here for debugging)
    uint8_t *mem = __va(fb->buffer);
    for(size_t y = 0; y < 200; y++) {
        memset(mem + (y * 320), (uint8_t)y, 320);
    }

    for(int i = 0; i < 256; i++) {
        uint8_t value = i;
        uint8_t r = ((value >> 0) & 0b111) << 3;
        uint8_t g = ((value >> 3) & 0b111) << 3;
        uint8_t b = ((value >> 6) & 0b11) << 4;
        vga_dac_set_color(vga, i, r, g, b);
    }

    vga_fb_flush_mode_graphics_320_200(fb);

    vga_screen_enable(vga);

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = 320 * 200,
    .layer_count = 1,
    .layer_infos = {
    {
        .format = FB_LAYER_FORMAT_BYTE_R3G3B2,
        .order = FB_LAYER_ORDER_ROW_MAJOR,
        .width = 320,
        .height = 200,
        .offset = 0,
        .stride = 1,
    },
    },
};

struct vga_fb_mode vga_fb_mode_graphics_320_200 = {
    .flush = vga_fb_flush_mode_graphics_320_200,
    .setup = vga_fb_setup_mode_graphics_320_200,
    .mode_info = &mode_info,
};


