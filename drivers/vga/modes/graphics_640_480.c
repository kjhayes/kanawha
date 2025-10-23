
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
vga_fb_flush_mode_graphics_640_480(
        struct vga_fb *fb)
{
//    vga_screen_disable(&fb->vga_dev);

    void __phys *vga_mem = (void __phys *)0xA0000;
    size_t bitbuffer_size = ((640*480)/8);

    if(!fb->buffer_exists) {
	return 0;
    }

    uint8_t *red_bitbuffer = kmalloc(bitbuffer_size, KM_KERNEL);
    uint8_t *green_bitbuffer = kmalloc(bitbuffer_size, KM_KERNEL);
    uint8_t *blue_bitbuffer = kmalloc(bitbuffer_size, KM_KERNEL);
    uint8_t *intensity_bitbuffer = kmalloc(bitbuffer_size, KM_KERNEL);

    if(red_bitbuffer == NULL ||
       green_bitbuffer == NULL ||
       blue_bitbuffer == NULL ||
       intensity_bitbuffer == NULL) {
	kfree(red_bitbuffer);
	kfree(green_bitbuffer);
	kfree(blue_bitbuffer);
	kfree(intensity_bitbuffer);
	return -ENOMEM;
    }
    
    for(size_t i = 0; i < bitbuffer_size; i++)
    {
	void __phys *buffer_loc = fb->buffer + (i*8);

	uint8_t red_bits = 0;
	uint8_t green_bits = 0;
	uint8_t blue_bits = 0;
	uint8_t intensity_bits = 0;

	le64_t le_quad;
	memcpy_pv(&le_quad, buffer_loc, sizeof(le_quad));
	uint64_t quad = letoh64(le_quad);

	for(size_t bit = 0; bit < 8; bit++) {
	    uint8_t bitshift = (7-bit);
	    red_bits       |= ((((quad >> (8*bit)) & 0b0001) >> 0) << bitshift);
	    green_bits     |= ((((quad >> (8*bit)) & 0b0010) >> 1) << bitshift);
	    blue_bits      |= ((((quad >> (8*bit)) & 0b0100) >> 2) << bitshift);
	    intensity_bits |= ((((quad >> (8*bit)) & 0b1000) >> 3) << bitshift);
	}

	red_bitbuffer[i] = red_bits;
	green_bitbuffer[i] = green_bits;
	blue_bitbuffer[i] = blue_bits;
	intensity_bitbuffer[i] = intensity_bits;
    }

    vga_write_field(&fb->vga_dev, MemoryPlaneWriteEnable, 0b0001);
    memcpy_vp(vga_mem, red_bitbuffer, bitbuffer_size);

    vga_write_field(&fb->vga_dev, MemoryPlaneWriteEnable, 0b0010);
    memcpy_vp(vga_mem, green_bitbuffer, bitbuffer_size);

    vga_write_field(&fb->vga_dev, MemoryPlaneWriteEnable, 0b0100);
    memcpy_vp(vga_mem, blue_bitbuffer, bitbuffer_size);

    vga_write_field(&fb->vga_dev, MemoryPlaneWriteEnable, 0b1000);
    memcpy_vp(vga_mem, intensity_bitbuffer, bitbuffer_size);

//    vga_screen_enable(&fb->vga_dev);

    kfree(red_bitbuffer);
    kfree(green_bitbuffer);
    kfree(blue_bitbuffer);
    kfree(intensity_bitbuffer);

    return 0;
}

static int
vga_fb_setup_mode_graphics_640_480(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = &fb->vga_dev;

    vga_screen_disable(vga);

    vga_write_field(vga, CRTCRegistersProtectEnable, 0);

    vga_write_register(vga,  AttributeModeControl,     0x01);
    vga_write_register(vga,  OverscanColor,            0x00);
    vga_write_register(vga,  ColorPlaneEnable,         0x0F);
    vga_write_register(vga,  HorizontalPixelPanning,   0x00);
    vga_write_register(vga,  ColorSelect,              0x00);
    vga_write_register(vga,  MiscellaneousOutput,      0xE3);
    vga_write_register(vga,  ClockingMode,             0x01);
    vga_write_register(vga,  CharacterMapSelect,       0x00);
    vga_write_register(vga,  SequencerMemoryMode,      0x02);
    vga_write_register(vga,  GraphicsMode,             0x00);
    vga_write_register(vga,  MiscellaneousGraphics,    0x05);
    vga_write_register(vga,  HorizontalTotal,          0x5F);
    vga_write_register(vga,  EndHorizontalDisplay,     0x4F);
    vga_write_register(vga,  StartHorizontalBlanking,  0x50);
    vga_write_register(vga,  EndHorizontalBlanking,    0x82);
    vga_write_register(vga,  StartHorizontalRetrace,   0x54);
    vga_write_register(vga,  EndHorizontalRetrace,     0x80);
    vga_write_register(vga,  VerticalTotal,            0x0B);
    vga_write_register(vga,  Overflow,                 0x3E);
    vga_write_register(vga,  PresetRowScan,            0x00);
    vga_write_register(vga,  MaximumScanLine,          0x40);
    vga_write_register(vga,  VerticalRetraceStart,     0xEA);
    vga_write_register(vga,  VerticalRetraceEnd,       0x8C & ~(0x80));
    vga_write_register(vga,  VerticalDisplayEnd,       0xDF);
    vga_write_register(vga,  Offset,                   0x28);
    vga_write_register(vga,  UnderlineLocation,        0x00);
    vga_write_register(vga,  StartVerticalBlanking,    0xE7);
    vga_write_register(vga,  EndVerticalBlanking,      0x04);
    vga_write_register(vga,  CRTCModeControl,          0xE3);

    vga_write_register(vga,  MapMask,                  0x0F); // Added
    vga_write_register(vga,  EnableSetReset,           0x00); // Added
    vga_write_register(vga,  SetReset,                 0x00); // Added
    vga_write_register(vga,  DataRotate,               0x00); // Added
    vga_write_register(vga,  ReadMapSelect,            0x00); // Added
    vga_write_register(vga,  ColorDontCare,            0x00); // Added
    vga_write_register(vga,  BitMask,                  0xFF); // Added
    vga_write_register(vga,  DACMask,                  0xFF); // Added

    // TEST
    vga_write_sequencer_register_set(vga, 0x00, 0x03);
    vga_write_sequencer_register_set(vga, 0x01, 0x01);
    vga_write_sequencer_register_set(vga, 0x02, 0x0F);
    vga_write_sequencer_register_set(vga, 0x03, 0x00);
    vga_write_sequencer_register_set(vga, 0x04, 0x06);

    vga_write_crt_register_set(vga, 0x00, 0x5F);
    vga_write_crt_register_set(vga, 0x01, 0x4F);
    vga_write_crt_register_set(vga, 0x02, 0x50);
    vga_write_crt_register_set(vga, 0x03, 0x82);
    vga_write_crt_register_set(vga, 0x04, 0x54);
    vga_write_crt_register_set(vga, 0x05, 0x80);
    vga_write_crt_register_set(vga, 0x06, 0x0B);
    vga_write_crt_register_set(vga, 0x07, 0x3E);
    vga_write_crt_register_set(vga, 0x08, 0x00);
    vga_write_crt_register_set(vga, 0x09, 0x40);
    vga_write_crt_register_set(vga, 0x0A, 0x00);
    vga_write_crt_register_set(vga, 0x0B, 0x00);
    vga_write_crt_register_set(vga, 0x0C, 0x00);
    vga_write_crt_register_set(vga, 0x0D, 0x00);
    vga_write_crt_register_set(vga, 0x0E, 0x00);
    vga_write_crt_register_set(vga, 0x0F, 0x59);
    vga_write_crt_register_set(vga, 0x10, 0xEA);
    vga_write_crt_register_set(vga, 0x11, 0x8C & ~(0x80));
    vga_write_crt_register_set(vga, 0x12, 0xDF);
    vga_write_crt_register_set(vga, 0x13, 0x28);
    vga_write_crt_register_set(vga, 0x14, 0x00);
    vga_write_crt_register_set(vga, 0x15, 0xE7);
    vga_write_crt_register_set(vga, 0x16, 0x04);
    vga_write_crt_register_set(vga, 0x17, 0xE3);
    vga_write_crt_register_set(vga, 0x18, 0xFF);

    vga_write_graphics_register_set(vga, 0, 0x00);
    vga_write_graphics_register_set(vga, 1, 0x00);
    vga_write_graphics_register_set(vga, 2, 0x00);
    vga_write_graphics_register_set(vga, 3, 0x00);
    vga_write_graphics_register_set(vga, 4, 0x00);
    vga_write_graphics_register_set(vga, 5, 0x00);
    vga_write_graphics_register_set(vga, 6, 0x05);
    vga_write_graphics_register_set(vga, 7, 0x0F);
    vga_write_graphics_register_set(vga, 8, 0xFF);
    
    vga_write_attribute_register_set(vga, 0x00, 0x00);
    vga_write_attribute_register_set(vga, 0x01, 0x01);
    vga_write_attribute_register_set(vga, 0x02, 0x02);
    vga_write_attribute_register_set(vga, 0x03, 0x03);
    vga_write_attribute_register_set(vga, 0x04, 0x04);
    vga_write_attribute_register_set(vga, 0x05, 0x05);
    vga_write_attribute_register_set(vga, 0x06, 0x14);
    vga_write_attribute_register_set(vga, 0x07, 0x07);
    vga_write_attribute_register_set(vga, 0x08, 0x38);
    vga_write_attribute_register_set(vga, 0x09, 0x39);
    vga_write_attribute_register_set(vga, 0x0A, 0x3A);
    vga_write_attribute_register_set(vga, 0x0B, 0x3B);
    vga_write_attribute_register_set(vga, 0x0C, 0x3C);
    vga_write_attribute_register_set(vga, 0x0D, 0x3D);
    vga_write_attribute_register_set(vga, 0x0E, 0x3E);
    vga_write_attribute_register_set(vga, 0x0F, 0x3F);
    vga_write_attribute_register_set(vga, 0x10, 0x01);
    vga_write_attribute_register_set(vga, 0x11, 0x00);
    vga_write_attribute_register_set(vga, 0x12, 0x0F);
    vga_write_attribute_register_set(vga, 0x13, 0x00);
    vga_write_attribute_register_set(vga, 0x14, 0x00);
    // END TEST

    // Set all 256 possible colors with the same 16-bit colors repeating
    for(int i = 0; i < 256; i++) {
        uint8_t value = i & 0xF;
	uint8_t intensity = (value >> 3) & 0b1;
	uint8_t intensity_mask = intensity ? 0x1F : 0x00;
        uint8_t r = (((value >> 0) & 0b1) << 5) | intensity_mask;
        uint8_t g = (((value >> 1) & 0b1) << 5) | intensity_mask;
        uint8_t b = (((value >> 2) & 0b1) << 5) | intensity_mask;
        vga_dac_set_color(vga, i, r, g, b);
    }

    vga_write_field(vga, CRTCRegistersProtectEnable, 1);

    if(fb->buffer_exists) {
	memset_p(fb->buffer, 0xF, 640*480);
    }

    vga_fb_flush_mode_graphics_640_480(fb);

    vga_screen_enable(vga);

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = 640 * 480,
    .layer_count = 1,
    .layer_infos = {
    {
	.layout = {
            .format = GFX_FORMAT_BYTE_R1G1B1I1,
            .order = GFX_ORDER_ROW_MAJOR,
            .width = 640,
            .height = 480,
            .offset = 0,
            .stride = 1,
	},
    },
    },
};

struct vga_fb_mode vga_fb_mode_graphics_640_480 = {
    .flush = vga_fb_flush_mode_graphics_640_480,
    .setup = vga_fb_setup_mode_graphics_640_480,
    .mode_info = &mode_info,
};

