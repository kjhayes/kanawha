
#include <drivers/vga/vga.h>
#include <drivers/fb/vga/font.h>
#include <kanawha/gfx/convert.h>
#include <kanawha/gfx/font.h>
#include <kanawha/gfx/layout.h>

int
vga_load_glyph(struct vga_dev *dev,
               char c,
               const uint8_t *glyph,
               size_t height,
               unsigned int character_set)
{
    if(character_set >= 8)
    {
        return -EINVAL;
    }

    const static size_t character_set_offsets[8] = {
        [0b000] = 0x0000,
        [0b001] = 0x4000,
        [0b010] = 0x8000,
        [0b011] = 0xC000,
        [0b100] = 0x2000,
        [0b101] = 0x6000,
        [0b110] = 0xA000,
        [0b111] = 0xE000,
    };

    size_t offset = (((size_t)(unsigned char)c) * 32) + character_set_offsets[character_set];

    // Enable plane 2 where the font data is stored
    vga_write_field(dev, MemoryPlaneWriteEnable, 0b0100);
    vga_write_field(dev, WriteMode, 0);
    vga_write_field(dev, HostOddEvenMemoryWriteAddressingDisable, 1);
    vga_write_field(dev, HostOddEvenMemoryReadAddressingEnable, 0);
    vga_write_field(dev, ChainOddEvenEnable, 0);

    for(size_t i = 0; i < 32; i++)
    {
        uint8_t data = 0x0;
        if(i < height)
        {
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

int
vga_load_font(struct vga_dev *vga,
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

    uint8_t char_buffer[8] = {0};

    for(size_t i = 0; i < 256; i++)
    {
        const uint8_t *data;
        if(i >= font->num_chars)
        {
            data = missing_char;
        }
        else
        {
            res = gfx_convert(&font->layout,
                              font->font_data + (font->char_byte_stride * i),
                              font->font_data_size,
                              &out_layout,
                              char_buffer,
                              sizeof(char_buffer));
            if(res)
            {
                return res;
            }

            data = char_buffer;
        }
        res = vga_load_glyph(vga, (char)i, data, 8, character_set);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

