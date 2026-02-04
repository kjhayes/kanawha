
#include <drivers/vga/vga.h>
#include <drivers/vga/fb.h>
#include <kanawha/dev/fb.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/endian.h>
#include <kanawha/gfx/font.h>
#include <kanawha/gfx/convert.h>
#include <kanawha/gfx/layout.h>

struct vga_fb;

static int
vga_fb_flush_mode_text_80_50(
        struct vga_fb *fb)
{
    vga_write_field(fb->vga_dev, MemoryPlaneWriteEnable, 0b0011);
    vga_screen_disable(fb->vga_dev);
    memcpy_pp((void __phys *)0xA0000, fb->buffer, 80*50*2);
    vga_screen_enable(fb->vga_dev);
    return 0;
}

static int
vga_load_glyph(
	struct vga_dev *dev,
	char c,
	const uint8_t *glyph,
	size_t height,
	unsigned int character_set
	)
{
    if(character_set >= 8) {
	return -EINVAL;
    }

    const static size_t character_set_offsets[8] =
    {
        [0b000] = 0x0000,
        [0b001] = 0x4000,
        [0b010] = 0x8000,
        [0b011] = 0xC000,
        [0b100] = 0x2000,
        [0b101] = 0x6000,
        [0b110] = 0xA000,
        [0b111] = 0xE000,
    };

    size_t offset = (((size_t)c) * 32) + character_set_offsets[character_set];

    // Enable plane 2 where the font data is stored
    vga_write_field(dev, MemoryPlaneWriteEnable, 0b0100);
    vga_write_field(dev, WriteMode, 0);
    vga_write_field(dev, HostOddEvenMemoryWriteAddressingDisable, 1);
    vga_write_field(dev, HostOddEvenMemoryReadAddressingEnable, 0);
    vga_write_field(dev, ChainOddEvenEnable, 0);
    

    for(size_t i = 0; i < 32; i++) {
	uint8_t data = 0x0;
	if(i < height) {
	    data = glyph[i];
	}
        memcpy_vp((void __phys *)0xA0000 + offset + i, &data, 1);
    }

    // Go back to regular text mode planes 0 and 1
    vga_write_field(dev, MemoryPlaneWriteEnable, 0b0011);
    vga_write_field(dev, HostOddEvenMemoryWriteAddressingDisable, 0);
    vga_write_field(dev, HostOddEvenMemoryReadAddressingEnable, 1);
    vga_write_field(dev, ChainOddEvenEnable, 1);

    return 0;
}

static int
vga_load_font(
	struct vga_dev *vga,
	unsigned int character_set,
	struct font *font)
{
    int res;

    const static uint8_t missing_char[8] = {
	0b00011000,
	0b00111100,
	0b01100110,
	0b11100111,
	0b11111111,
	0b01100110,
	0b00111100,
	0b00011000,
    };

    static struct gfx_layout out_layout = {
	.order = GFX_ORDER_ROW_MAJOR,
	.format = GFX_FORMAT_BIT_MONO,
	.width = 8,
	.height = 8,
	.stride = 1,
	.offset = 0,
    };

    uint8_t char_buffer[8] = { 0 };

    for(size_t i = 0; i < 256; i++) {
	const uint8_t *data;
	if(i >= font->num_chars) {
	    data = missing_char;
	} else { 
	    res = gfx_convert(
		    &font->layout,
		    font->font_data + (font->char_byte_stride * i),
		    font->font_data_size,
		    &out_layout,
		    char_buffer,
		    sizeof(char_buffer));
	    if(res) {
		return res;
	    }

	    data = char_buffer;
	}
        res = vga_load_glyph(
        	vga,
        	(char)i,
        	data,
        	8,
        	character_set
        	);
	if(res) {
	    return res;
	}
    }

    return 0;
}

static int
vga_fb_setup_mode_text_80_50(
        struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = fb->vga_dev;

    vga_screen_disable(vga);

    vga_write_field(vga, CRTCRegistersProtectEnable, 0);

    vga_write_register(vga,  AttributeModeControl,     0x04);
    vga_write_register(vga,  OverscanColor,            0x00);
    vga_write_register(vga,  ColorPlaneEnable,         0x0F);
    vga_write_register(vga,  HorizontalPixelPanning,   0x08);
    vga_write_register(vga,  ColorSelect,              0x00);
    vga_write_register(vga,  MiscellaneousOutput,      0x67);
    vga_write_register(vga,  ClockingMode,             0x00);
    vga_write_register(vga,  CharacterMapSelect,       0x00);
    vga_write_register(vga,  SequencerMemoryMode,      0x04); // OSDev Claims this should be 0x7
    vga_write_register(vga,  GraphicsMode,             0x10);
    vga_write_register(vga,  MiscellaneousGraphics,    0x06);
    vga_write_register(vga,  HorizontalTotal,          0x5F);
    vga_write_register(vga,  EndHorizontalDisplay,     0x4F);
    vga_write_register(vga,  StartHorizontalBlanking,  0x50);
    vga_write_register(vga,  EndHorizontalBlanking,    0x82);
    vga_write_register(vga,  StartHorizontalRetrace,   0x55);
    vga_write_register(vga,  EndHorizontalRetrace,     0x81);
    vga_write_register(vga,  VerticalTotal,            0xBF);
    vga_write_register(vga,  Overflow,                 0x1F);
    vga_write_register(vga,  PresetRowScan,            0x00);
    vga_write_register(vga,  MaximumScanLine,          0x4F);
    vga_write_register(vga,  VerticalRetraceStart,     0x9C);
    vga_write_register(vga,  VerticalRetraceEnd,       0x8E & ~(0x80));
    vga_write_register(vga,  VerticalDisplayEnd,       0x8F);
    vga_write_register(vga,  Offset,                   0x28);
    vga_write_register(vga,  UnderlineLocation,        0x1F);
    vga_write_register(vga,  StartVerticalBlanking,    0x96);
    vga_write_register(vga,  EndVerticalBlanking,      0xB9);
    vga_write_register(vga,  CRTCModeControl,          0xA3);

    vga_write_register(vga,  CursorStart,              0x20); // Added
    vga_write_register(vga,  MapMask,                  0x03); // Added
    vga_write_register(vga,  EnableSetReset,           0x00); // Added
    vga_write_register(vga,  SetReset,                 0x00); // Added
    vga_write_register(vga,  DataRotate,               0x00); // Added
    vga_write_register(vga,  ReadMapSelect,            0x00); // Added
    vga_write_register(vga,  ColorDontCare,            0x00); // Added
    vga_write_register(vga,  BitMask,                  0xFF); // Added
    vga_write_register(vga,  DACMask,                  0xFF); // Added

    // Changes from 80x25
    vga_write_field(vga, MaximumScanLine, 7); // 8x8

    vga_write_field(fb->vga_dev, MemoryMapSelect, 1);

    // Load a font
    for(size_t cs = 0; cs < 8; cs++) {
	vga_load_font(vga, cs, &kanawha_default_font);
    }

    // Clear every attribute to be black background, white foreground
    for(size_t i = 0; i < 80*50; i++) {
	uint8_t default_attr = 0x0F;
	memcpy_vp((fb->buffer+(i*2)+1), &default_attr, 1);
    }

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

    // Set up an initial message on the screen
    {
//	size_t cursor_x = 0;
//	size_t cursor_y = 0;
//
//#define PUTC(_c)\
//	do {\
//	    char __c = _c;\
//	    if(__c == '\n') {\
//	        cursor_x = 0;\
//	        cursor_y++;\
//	        if(cursor_x >= 80) {\
//	            cursor_x = 0;\
//	            cursor_y++;\
//	        }\
//	        if(cursor_y >= 50) {\
//	            cursor_y = 50;\
//	        }\
//	        break;\
//	    }\
//	    memcpy_vp((void __phys*)fb->buffer + ((cursor_x + (cursor_y * 80))*2), &__c, 1);\
//	    cursor_x++;\
//	    if(cursor_x >= 80) {\
//	        cursor_x = 0;\
//	        cursor_y++;\
//	    }\
//	    if(cursor_y >= 50) {\
//	        cursor_y = 50;\
//	    }\
//	} while(0)
//
//#define PUTS(__str)\
//	do {\
//	    char *iter = __str;\
//	    while(*iter) {\
//		PUTC(*iter);\
//		iter++;\
//	    }\
//	} while(0)
//
//	PUTS("Kanawha Kernel VGA Text Mode Driver\n");
//	for(size_t i = 0; i < 256; i++) {
//	    if(i == '\n') {
//		continue;
//	    } else {
//	        PUTC((char)i);
//	    }
//	}
//
//#undef PUTC
//#undef PUTS
    }

    vga_screen_enable(vga);

    res = vga_fb_flush_mode_text_80_50(fb);
    if(res) {
        wprintk("Failed to flush VGA framebuffer after mode-setting (err=%s)!\n",
                errnostr(res));
    }

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = 80*50*2,
    .layer_count = 2,
    .layer_infos = {
        {
	    .layout = {
                .format = GFX_FORMAT_VGA_CHAR,
                .order = GFX_ORDER_ROW_MAJOR,
                .width = 80,
                .height = 50,
                .offset = 0,
                .stride = 2,
	    },
        },
        {
	    .layout = {
                .format = GFX_FORMAT_VGA_ATTR,
                .order = GFX_ORDER_ROW_MAJOR,
                .width = 80,
                .height = 50,
                .offset = 1,
                .stride = 2,
	    },
        },
    },
};

struct vga_fb_mode 
vga_fb_mode_text_80_50 = {
    .flush = vga_fb_flush_mode_text_80_50,
    .setup = vga_fb_setup_mode_text_80_50,
    .mode_info = &mode_info,
};

