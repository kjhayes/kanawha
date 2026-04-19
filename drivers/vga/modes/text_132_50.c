
#include <drivers/vga/fb.h>
#include <drivers/vga/vga.h>
#include <drivers/vga/font.h>
#include <kanawha/dev/fb.h>
#include <kanawha/endian.h>
#include <kanawha/gfx/convert.h>
#include <kanawha/gfx/font.h>
#include <kanawha/gfx/layout.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>

struct vga_fb;

#define WIDTH 132
#define HEIGHT 50

static int
vga_fb_flush_mode_text_132_50(struct vga_fb *fb)
{
    vga_write_field(fb->vga_dev, MemoryPlaneWriteEnable, 0b0011);
    vga_screen_disable(fb->vga_dev);
    memcpy_pp((void __phys *)0xA0000, fb->buffer, WIDTH * HEIGHT * 2);
    vga_screen_enable(fb->vga_dev);
    return 0;
}

static int
vga_fb_setup_mode_text_132_50(struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = fb->vga_dev;

    vga_screen_disable(vga);

    vga_write_field(vga, CRTCRegistersProtectEnable, 0);

    vga_write_register(vga, AttributeModeControl, 0x04);
    vga_write_register(vga, OverscanColor, 0x00);
    vga_write_register(vga, ColorPlaneEnable, 0x0F);
    vga_write_register(vga, HorizontalPixelPanning, 0x08);
    vga_write_register(vga, ColorSelect, 0x00);
    vga_write_register(vga, MiscellaneousOutput, 0x67);
    vga_write_register(vga, ClockingMode, 0x00);
    vga_write_register(vga, CharacterMapSelect, 0x00);
    vga_write_register(vga,
                       SequencerMemoryMode,
                       0x04); // OSDev Claims this should be 0x7
    vga_write_register(vga, GraphicsMode, 0x10);
    vga_write_register(vga, MiscellaneousGraphics, 0x06);
    vga_write_register(vga, HorizontalTotal, 0x5F);
    vga_write_register(vga, EndHorizontalDisplay, 0x4F);
    vga_write_register(vga, StartHorizontalBlanking, 0x50);
    vga_write_register(vga, EndHorizontalBlanking, 0x82);
    vga_write_register(vga, StartHorizontalRetrace, 0x55);
    vga_write_register(vga, EndHorizontalRetrace, 0x81);
    vga_write_register(vga, VerticalTotal, 0xBF);
    vga_write_register(vga, Overflow, 0x1F);
    vga_write_register(vga, PresetRowScan, 0x00);
    vga_write_register(vga, MaximumScanLine, 0x4F);
    vga_write_register(vga, VerticalRetraceStart, 0x9C);
    vga_write_register(vga, VerticalRetraceEnd, 0x8E & ~(0x80));
    vga_write_register(vga, VerticalDisplayEnd, 0x8F);
    vga_write_register(vga, Offset, 0x28);
    vga_write_register(vga, UnderlineLocation, 0x1F);
    vga_write_register(vga, StartVerticalBlanking, 0x96);
    vga_write_register(vga, EndVerticalBlanking, 0xB9);
    vga_write_register(vga, CRTCModeControl, 0xA3);

    vga_write_register(vga, CursorStart, 0x20);    // Added
    vga_write_register(vga, MapMask, 0x03);        // Added
    vga_write_register(vga, EnableSetReset, 0x00); // Added
    vga_write_register(vga, SetReset, 0x00);       // Added
    vga_write_register(vga, DataRotate, 0x00);     // Added
    vga_write_register(vga, ReadMapSelect, 0x00);  // Added
    vga_write_register(vga, ColorDontCare, 0x00);  // Added
    vga_write_register(vga, BitMask, 0xFF);        // Added
    vga_write_register(vga, DACMask, 0xFF);        // Added

    // Changes from 80x25
    vga_write_field(vga, MaximumScanLine, 7); // 8x8

    // Changes from 80x50
    vga_write_field(vga, HorizontalTotal, WIDTH - 5);
    vga_write_field(vga, EndHorizontalDisplay, WIDTH - 1);
    vga_write_field(vga, StartHorizontalBlanking, WIDTH); // Do not blank
    vga_write_field(vga,
                    EndHorizontalBlanking,
                    (WIDTH & 0b111111) + 0);             // Do not blank
    vga_write_field(vga, StartHorizontalRetrace, WIDTH); // Do not retrace
    vga_write_field(vga,
                    EndHorizontalRetrace,
                    (WIDTH & 0b11111) + 0); // Do not retrace
    vga_write_field(vga, DisplayEnableSkew, 0);
    vga_write_field(vga, Offset, WIDTH / 2);

    vga_write_field(fb->vga_dev, MemoryMapSelect, 1);

    // Load a font
    for(size_t cs = 0; cs < 8; cs++)
    {
        vga_load_font(vga, cs, &kanawha_default_font);
    }

    // Clear every attribute to be black background, white foreground
    for(size_t i = 0; i < WIDTH * HEIGHT; i++)
    {
        uint8_t default_attr = 0x0F;
        memcpy_vp((fb->buffer + (i * 2) + 1), &default_attr, 1);
    }

    // Set all 256 possible colors with the same 16-bit colors repeating
    for(int i = 0; i < 256; i++)
    {
        uint8_t value = i & 0xF;
        uint8_t intensity = (value >> 3) & 0b1;
        uint8_t intensity_mask = intensity ? 0x1F : 0x00;
        uint8_t r = (((value >> 0) & 0b1) << 5) | intensity_mask;
        uint8_t g = (((value >> 1) & 0b1) << 5) | intensity_mask;
        uint8_t b = (((value >> 2) & 0b1) << 5) | intensity_mask;
        vga_dac_set_color(vga, i, r, g, b);
    }

    vga_write_field(vga, CRTCRegistersProtectEnable, 1);

    vga_screen_enable(vga);

    res = vga_fb_flush_mode_text_132_50(fb);
    if(res)
    {
        wprintk("Failed to flush VGA framebuffer after mode-setting "
                "(err=%s)!\n",
                errnostr(res));
    }

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = WIDTH * HEIGHT * 2,
    .layer_count = 2,
    .layer_infos =
        {
            {
                .layout =
                    {
                        .format = GFX_FORMAT_VGA_CHAR,
                        .order = GFX_ORDER_ROW_MAJOR,
                        .width = WIDTH,
                        .height = HEIGHT,
                        .offset = 0,
                        .stride = 2,
                    },
            },
            {
                .layout =
                    {
                        .format = GFX_FORMAT_VGA_ATTR,
                        .order = GFX_ORDER_ROW_MAJOR,
                        .width = WIDTH,
                        .height = HEIGHT,
                        .offset = 1,
                        .stride = 2,
                    },
            },
        },
};

struct vga_fb_mode vga_fb_mode_text_132_50 = {
    .flush = vga_fb_flush_mode_text_132_50,
    .setup = vga_fb_setup_mode_text_132_50,
    .mode_info = &mode_info,
};
