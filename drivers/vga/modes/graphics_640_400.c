
#include <drivers/vga/fb.h>
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>

struct vga_fb;

#define HRES 640
#define VRES 400

static int
vga_fb_flush_graphics_640_400(
        struct vga_fb *fb)
{
    uint8_t *vga_mem = __va((void __phys *)0xA0000);
    uint8_t *buffer = __va(fb->buffer);
    vga_screen_disable(&fb->vga_dev);
    for(int shift = 0; shift < 4; shift++) {
        vga_set_write_planes(&fb->vga_dev, 1<<shift);
        for(size_t i = 0; i < (HRES*VRES)/8; i++) {
            uint8_t *pixels = &buffer[i*8];
            uint8_t data = 0;
            for(int bit = 0; bit < 8; bit++) {
                data <<= 1;
                data |= (pixels[bit] >> shift) & 0b1;
            }
//            if(data != 0x0) {
//                printk("Writing: 0x%x to plane %d offset=0x%x\n",
//                    data, shift, i);
//            }
            vga_mem[i] = data;
        }
    }
    vga_set_write_planes(&fb->vga_dev, 0b0000);
    vga_screen_enable(&fb->vga_dev);
    return 0;
}

static int
vga_fb_setup_graphics_640_400(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    vga_screen_disable(vga);

    vga_enable_planar(vga);
    vga_disable_even_odd(vga);

    vga_write_field(vga, WriteMode, 0);
    vga_set_write_planes(vga, 0b0);
    vga_set_color_planes(vga, 0b1111);

    vga_write_field(vga, ReadMode, 0);
    vga_write_field(vga, AlphanumericModeDisable, 1);

    vga_set_color_mode_pop_1(vga);
    vga_disable_8_bit_color(vga);

    vga_set_horizontal_panning(vga, 0);
    vga_disable_half_rate_dot_clock(vga);
    vga_enable_8_dot_mode(vga);

    vga_unlock_crt_reg(vga);

    vga_crt_disable_retrace(vga);

    // Because we are using 256 color mode, we need to double the "horizontal resolution" our timings are targeting
    static const uint16_t effective_hres = HRES;
    static const uint16_t effective_vres = VRES;
    static const uint16_t hblank = 32;
    static const uint16_t vblank = 32;
    vga_crt_set_horizontal_total(vga, (effective_hres + hblank) / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_total(vga, (effective_vres + vblank));

    vga_crt_set_horizontal_display_end(vga, effective_hres / vga_get_dots_per_character(vga));
    vga_crt_set_vertical_display_end(vga, effective_vres);

    vga_crt_set_horizontal_blanking_start(vga, effective_hres / vga_get_dots_per_character(vga));
    vga_crt_set_horizontal_blanking_end(vga, hblank / vga_get_dots_per_character(vga));

    vga_crt_set_vertical_blanking_start(vga, effective_vres);
    vga_crt_set_vertical_blanking_end(vga, vblank);
    
    vga_crt_disable_scan_doubling(vga);
    vga_crt_set_maximum_scanline(vga, 0);
    vga_crt_set_address_size(vga, 4);
    vga_crt_set_scanline_offset(
            vga,
            HRES/(4*2) // "address" length of a scanline
            );

    vga_lock_crt_reg(vga);

    for(uint8_t index = 0; index < 16; index++) {
        uint16_t r = (index>>0) & 0b1;
        uint16_t g = (index>>1) & 0b1;
        uint16_t b = (index>>2) & 0b1;
        uint16_t i = (index>>3) & 0b1;
        r *= i ? 0b111111 : 0b011111;
        g *= i ? 0b111111 : 0b011111;
        b *= i ? 0b111111 : 0b011111;
        vga_dac_set_color(vga, index, r, g, b);
    }

    vga_fb_flush_graphics_640_400(fb);

    vga_screen_enable(vga);

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = HRES * VRES,
    .layer_count = 1,
    .layer_infos = {
    {
        .format = FB_LAYER_FORMAT_BYTE_R1G1B1I1,
        .order = FB_LAYER_ORDER_ROW_MAJOR,
        .width = HRES,
        .height = VRES,
        .offset = 0,
        .stride = 1,
    },
    },
};

struct vga_fb_mode vga_fb_mode_graphics_640_400 = {
    .flush = vga_fb_flush_graphics_640_400,
    .setup = vga_fb_setup_graphics_640_400,
    .mode_info = &mode_info,
};

