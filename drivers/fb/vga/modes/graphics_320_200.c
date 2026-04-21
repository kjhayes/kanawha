
#include <drivers/fb/vga/vga.h>
#include <drivers/fb/vga/font.h>
#include <drivers/vga/vga.h>
#include <kanawha/dev/fb.h>
#include <kanawha/endian.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>

static int
vga_fb_flush_mode_graphics_320_200(struct vga_fb *fb)
{
    //    vga_screen_disable(fb->vga_dev);
    memcpy_pp((void __phys *)0xA0000, fb->buffer, 320 * 200);
    //    vga_screen_enable(fb->vga_dev);
    return 0;
}

static int
vga_fb_setup_mode_graphics_320_200(struct vga_fb *fb)
{
    int res;
    struct vga_dev *vga = fb->vga_dev;

    vga_screen_disable(vga);
    // text  12h     13h     X
    // 0x0C         0x01         0x41         0x41
    // 0x00         0x00         0x00         0x00
    // 0x0F         0x0F         0x0F         0x0F
    // 0x08         0x00         0x00         0x00
    // 0x00         0x00         0x00         0x00
    // 0x67         0xE3         0x63         0xE3
    // 0x00         0x01         0x01         0x01
    // 0x00         0x00         0x00         0x00
    // 0x07         0x02         0x0E         0x06
    // 0x10         0x00         0x40         0x40
    // 0x0E         0x05         0x05         0x05
    // 0x5F         0x5F         0x5F         0x5F
    // 0x4F         0x4F         0x4F         0x4F
    // 0x50         0x50         0x50         0x50
    // 0x82         0x82         0x82         0x82
    // 0x55         0x54         0x54         0x54
    // 0x81         0x80         0x80         0x80
    // 0xBF         0x0B         0xBF         0x0D
    // 0x1F         0x3E         0x1F         0x3E
    // 0x00         0x00         0x00         0x00
    // 0x4F         0x40         0x41         0x41
    // 0x9C         0xEA         0x9C         0xEA
    // 0x8E         0x8C         0x8E         0xAC
    // 0x8F         0xDF         0x8F         0xDF
    // 0x28         0x28         0x28         0x28
    // 0x1F         0x00         0x40         0x00
    // 0x96         0xE7         0x96         0xE7
    // 0xB9         0x04         0xB9         0x06
    // 0xA3         0xE3         0xA3         0xE3

    vga_write_field(vga, CRTCRegistersProtectEnable, 0);

    vga_write_register(vga, AttributeModeControl, 0x41);
    vga_write_register(vga, OverscanColor, 0x00);
    vga_write_register(vga, ColorPlaneEnable, 0x0F);
    vga_write_register(vga, HorizontalPixelPanning, 0x00);
    vga_write_register(vga, ColorSelect, 0x00);
    vga_write_register(vga, MiscellaneousOutput, 0x63);
    vga_write_register(vga, ClockingMode, 0x01);
    vga_write_register(vga, CharacterMapSelect, 0x00);
    vga_write_register(vga, SequencerMemoryMode, 0x0C);
    vga_write_register(vga, GraphicsMode, 0x40);
    vga_write_register(vga, MiscellaneousGraphics, 0x05);
    vga_write_register(vga, HorizontalTotal, 0x5F);
    vga_write_register(vga, EndHorizontalDisplay, 0x4F);
    vga_write_register(vga, StartHorizontalBlanking, 0x50);
    vga_write_register(vga, EndHorizontalBlanking, 0x82);
    vga_write_register(vga, StartHorizontalRetrace, 0x54);
    vga_write_register(vga, EndHorizontalRetrace, 0x80);
    vga_write_register(vga, VerticalTotal, 0xBF);
    vga_write_register(vga, Overflow, 0x1F);
    vga_write_register(vga, PresetRowScan, 0x00);
    vga_write_register(vga, MaximumScanLine, 0x41);
    vga_write_register(vga, VerticalRetraceStart, 0x9C);
    vga_write_register(vga, VerticalRetraceEnd, 0x8E & ~(0x80));
    vga_write_register(vga, VerticalDisplayEnd, 0x8F);
    vga_write_register(vga, Offset, 0x28);
    vga_write_register(vga, UnderlineLocation, 0x40);
    vga_write_register(vga, StartVerticalBlanking, 0x96);
    vga_write_register(vga, EndVerticalBlanking, 0xB9);
    vga_write_register(vga, CRTCModeControl, 0xA3);

    vga_write_register(vga, MapMask, 0x0F);        // Added
    vga_write_register(vga, EnableSetReset, 0x00); // Added
    vga_write_register(vga, SetReset, 0x00);       // Added
    vga_write_register(vga, DataRotate, 0x00);     // Added
    vga_write_register(vga, ReadMapSelect, 0x00);  // Added
    vga_write_register(vga, ColorDontCare, 0x00);  // Added
    vga_write_register(vga, BitMask, 0xFF);        // Added
    vga_write_register(vga, DACMask, 0xFF);        // Added

    for(int i = 0; i < 256; i++)
    {
        uint8_t value = i;
        uint8_t r = ((value >> 0) & 0b111) << 3;
        uint8_t g = ((value >> 3) & 0b111) << 3;
        uint8_t b = ((value >> 6) & 0b11) << 4;
        // For some reason this mode flips R and G with QEMU
        vga_dac_set_color(vga, i, r, g, b);
    }

    vga_write_field(vga, CRTCRegistersProtectEnable, 1);

    vga_fb_flush_mode_graphics_320_200(fb);

    vga_screen_enable(vga);

    return 0;
}

static struct fb_mode_info mode_info = {
    .buffer_size = 320 * 200,
    .layer_count = 1,
    .layer_infos =
        {
            {
                .layout =
                    {
                        .format = GFX_FORMAT_BYTE_R3G3B2,
                        .order = GFX_ORDER_ROW_MAJOR,
                        .width = 320,
                        .height = 200,
                        .offset = 0,
                        .stride = 1,
                    },
            },
        },
};

struct vga_fb_mode vga_fb_mode_graphics_320_200 = {
    .flush = vga_fb_flush_mode_graphics_320_200,
    .setup = vga_fb_setup_mode_graphics_320_200,
    .mode_info = &mode_info,
};
