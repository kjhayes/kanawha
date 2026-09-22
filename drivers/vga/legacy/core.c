
#include <drivers/vga/legacy.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>

static unsigned legacy_vga_cursor_x = 0;
static unsigned legacy_vga_cursor_y = 0;

static inline uint16_t
legacy_vga_encode(uint8_t c, uint8_t attr)
{
    return (((uint16_t)attr) << 8) | c;
}

static inline uint8_t
legacy_vga_attr_invert(uint8_t attr)
{
    return (uint8_t)(((attr & 0xF)<<4) | ((attr & 0xF0)>>4));
}

static int
legacy_vga_setchar_raw(uint8_t c, uint8_t attr, unsigned x, unsigned y)
{
    if(x >= LEGACY_VGA_RAW_WIDTH)
    {
        return -EINVAL;
    }
    if(y >= LEGACY_VGA_RAW_HEIGHT)
    {
        return -EINVAL;
    }

    uint16_t *framebuffer =
        (void *)__va((void __phys *)CONFIG_LEGACY_VGA_BASE_ADDRESS);
    framebuffer[x + (y * LEGACY_VGA_RAW_WIDTH)] = legacy_vga_encode(c, attr);

    return 0;
}
static uint16_t
legacy_vga_get_value_raw(unsigned x, unsigned y)
{
    if(x >= LEGACY_VGA_RAW_WIDTH)
    {
        return 0;
    }
    if(y >= LEGACY_VGA_RAW_HEIGHT)
    {
        return 0;
    }

    uint16_t *framebuffer =
        (void *)__va((void __phys *)CONFIG_LEGACY_VGA_BASE_ADDRESS);
    return framebuffer[x + (y * LEGACY_VGA_RAW_WIDTH)];
}

static int
legacy_vga_xlate_pos(
        unsigned x,
        unsigned y,
        unsigned *x_out,
        unsigned *y_out)
{
    if(x >= LEGACY_VGA_WIDTH) {
        return -EINVAL;
    }
    if(y >= LEGACY_VGA_HEIGHT) {
        return -EINVAL;
    }

    if(y >= LEGACY_VGA_RAW_HEIGHT) {
        // Adjust for Right Column
        x += LEGACY_VGA_WIDTH;
        y -= LEGACY_VGA_RAW_HEIGHT;
    }

    if(x_out) {*x_out = x;}
    if(y_out) {*y_out = y;}

    return 0;
}

int
legacy_vga_setchar(uint8_t c, uint8_t attr, unsigned x, unsigned y)
{
    int res;

    if(y >= LEGACY_VGA_RAW_HEIGHT) {
        attr = legacy_vga_attr_invert(attr);
    }

    unsigned raw_x, raw_y;

    res = legacy_vga_xlate_pos(x,y,&raw_x,&raw_y);
    if(res) {
        return res;
    }

    return legacy_vga_setchar_raw(c, attr, raw_x, raw_y);
}

uint8_t
legacy_vga_getchar(unsigned x, unsigned y)
{
    int res;
    
    unsigned raw_x, raw_y;

    res = legacy_vga_xlate_pos(x,y,&raw_x,&raw_y);
    if(res) {
        return ' ';
    }

    uint16_t raw = legacy_vga_get_value_raw(raw_x, raw_y);
    return raw & 0xFF;
}

uint8_t
legacy_vga_getattr(unsigned x, unsigned y)
{
    int res;

    unsigned raw_x, raw_y;

    res = legacy_vga_xlate_pos(x,y,&raw_x,&raw_y);
    if(res) {
        return ' ';
    }

    uint16_t raw = legacy_vga_get_value_raw(raw_x, raw_y);
    uint8_t attr = (raw>>8) & 0xFF;

    if(y >= LEGACY_VGA_RAW_HEIGHT) {
        attr = legacy_vga_attr_invert(attr);
    }

    return attr;
}

void
legacy_vga_clear(uint8_t c, uint8_t attr)
{
    for(unsigned y = 0; y < LEGACY_VGA_HEIGHT; y++)
    {
        for(unsigned x = 0; x < LEGACY_VGA_WIDTH; x++)
        {
            legacy_vga_setchar(c, attr, x, y);
        }
    }
}

void
legacy_vga_shift_up(uint8_t c, uint8_t attr)
{
    for(unsigned y = 1; y < LEGACY_VGA_HEIGHT; y++)
    {
        for(unsigned x = 0; x < LEGACY_VGA_WIDTH; x++)
        {
            uint8_t c_c = legacy_vga_getchar(x,y);
            uint8_t c_attr = legacy_vga_getattr(x,y);
            legacy_vga_setchar(c_c, c_attr, x, y-1);
        }
    }

    for(unsigned x = 0; x < LEGACY_VGA_WIDTH; x++)
    {
        legacy_vga_setchar(c, attr, x, LEGACY_VGA_HEIGHT - 1);
    }
}

void
legacy_vga_newline(uint8_t c, uint8_t attr)
{
    legacy_vga_cursor_x = 0;
    legacy_vga_cursor_y += 1;
    if(legacy_vga_cursor_y >= LEGACY_VGA_HEIGHT)
    {
        legacy_vga_cursor_y = LEGACY_VGA_HEIGHT - 1;
        legacy_vga_shift_up(c, attr);
    }
}

void
legacy_vga_putchar(char c, uint8_t attr)
{
    switch(c)
    {
        case '\n':
        {
            legacy_vga_newline(' ', attr);
        }
        return;

        case '\r':
        {
            legacy_vga_cursor_x = 0;
        }
        return;

        case '\t':
        {
            unsigned tab_align = legacy_vga_cursor_x % 4;
            for(unsigned spaces = 4 - tab_align; spaces > 0; spaces--)
            {
                legacy_vga_putchar(' ', attr);
            }
        }
        return;

        case '\b':
        {
            if(legacy_vga_cursor_x > 0) {
                legacy_vga_cursor_x--;
            } else {
                legacy_vga_cursor_x = LEGACY_VGA_WIDTH-1;
                if(legacy_vga_cursor_y > 0) {
                    legacy_vga_cursor_y--;
                } else {
                    legacy_vga_cursor_y = 0;
                }
            }
            legacy_vga_setchar(' ', attr, legacy_vga_cursor_x, legacy_vga_cursor_y);
        }
        return;
    }

    // Regular character to echo
    if(legacy_vga_cursor_x >= LEGACY_VGA_WIDTH)
    {
        legacy_vga_newline(' ', attr);
    }

    legacy_vga_setchar(c, attr, legacy_vga_cursor_x, legacy_vga_cursor_y);
    legacy_vga_cursor_x++;
}

