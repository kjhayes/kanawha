
#include <kanawha/char_dev.h>
#include <kanawha/init.h>
#include <kanawha/mmio.h>

static inline uint16_t
vga_encode(uint8_t c, uint8_t attr) {
    return (((uint16_t)attr) << 8) | c;
}

struct vga_serial
{
    uint16_t __mmio *framebuffer;

    uint16_t cursor_x;
    uint16_t cursor_y;
    uint16_t width;
    uint16_t height;

    uint16_t default_attr;

    struct char_dev char_dev;
};

static inline int
vga_serial_setchar(
        struct vga_serial *serial,
        uint16_t x,
        uint16_t y,
        uint8_t c,
        uint16_t attr)
{
    if(x >= serial->width) {
        return -EINVAL;
    }
    if(y >= serial->height) {
        return -EINVAL;
    }

    uint16_t encoded = vga_encode(c, attr);
    uint16_t __mmio *ptr = serial->framebuffer + (x  + (y * serial->width));
    mmio_writew(ptr, encoded);

    return 0;
}

static inline int
vga_serial_clear(
        struct vga_serial *serial,
        uint8_t c,
        uint16_t attr)
{
    for(uint32_t y = 0; y < serial->height; y++) {
        for(uint32_t x = 0; x < serial->width; x++) {
            vga_serial_setchar(serial, x, y, c, attr);
        }
    }
    return 0;
}

static inline int
vga_serial_shift_up(
        struct vga_serial *serial,
        uint8_t c,
        uint16_t attr)
{
    for(unsigned y = 1; y < serial->height; y++) {
        for(unsigned x = 0; x < serial->width; x++) {
            uint16_t __mmio *dst =
                ((uint16_t __mmio*)serial->framebuffer)
                +(x+((y-1)*serial->width));
            uint16_t __mmio *src =
                ((uint16_t __mmio*)serial->framebuffer)
                +(x+(y*serial->width));
            mmio_writew(dst, mmio_readw(src));
        }
    }

    for(unsigned x = 0; x < serial->width; x++) {
        vga_serial_setchar(serial, x, serial->height-1, c, attr);
    }

    return 0;
}

static inline int
vga_serial_newline(
        struct vga_serial *serial,
        uint8_t c,
        uint8_t attr)
{
    while(serial->cursor_x < serial->width) {
        vga_serial_setchar(
                serial,
                serial->cursor_x,
                serial->cursor_y,
                ' ', attr);
        serial->cursor_x++;
    }
    serial->cursor_x = 0;

    serial->cursor_y += 1;
    if(serial->cursor_y >= serial->height) {
        serial->cursor_y = serial->height-1;
        vga_serial_shift_up(serial, c, attr);
    }
    return 0;
}

static inline int
vga_serial_putchar(
        struct vga_serial *serial,
        char c,
        uint8_t attr) 
{
    int res;
    if(c == '\n') {
        vga_serial_newline(serial, ' ', attr);
        return 0;
    } else if(c == '\r') {
        serial->cursor_x = 0;
        return 0;
    }
    else if(c == '\t') {
        unsigned tab_align = serial->cursor_x % 4;
        unsigned spaces = 4 - tab_align;
        while(spaces > 0) {
            vga_serial_putchar(serial, ' ', attr);
            spaces--;
        }
        return 0;
    }

    if(serial->cursor_x >= serial->width) {
        vga_serial_newline(serial, ' ', attr);
    }

    res = vga_serial_setchar(serial, serial->cursor_x, serial->cursor_y, c, attr);
    if(res) {
        return res;
    }
    serial->cursor_x++;
    return 0;
}

static size_t
vga_serial_char_dev_read(
        struct char_dev *dev,
        void *buffer,
        size_t amount)
{
    return 0;
}

static size_t
vga_serial_char_dev_write(
        struct char_dev *dev,
        void *buffer,
        size_t amount)
{
    int res;
    struct vga_serial *serial =
        container_of(dev, struct vga_serial, char_dev);

    const char *data = buffer;

    size_t written = 0;
    while(written < amount) {
        res = vga_serial_putchar(serial, data[written], serial->default_attr);
        if(res) {
            break;
        }
        written++;
    }

    return written;
}

static int
vga_serial_char_dev_flush(
        struct char_dev *dev)
{
    // TODO: might not be needed but would be nice
    return 0;
}

static struct char_driver
vga_serial_driver = {
    .read = vga_serial_char_dev_read,
    .write = vga_serial_char_dev_write,
    .flush = vga_serial_char_dev_flush,
};

#ifdef CONFIG_X64

#define X64_SERIAL_VGA_ATTR_FG 0x09
#define X64_SERIAL_VGA_ATTR_BG 0x00

static struct vga_serial
x64_platform_vga = {
    .width = 80,
    .height = 25,
    .cursor_x = 0,
    .cursor_y = 0,
    .framebuffer = NULL,
    .default_attr = (X64_SERIAL_VGA_ATTR_FG | X64_SERIAL_VGA_ATTR_BG),
};

static int
x64_platform_vga_serial_register(void)
{
    int res;

    x64_platform_vga.framebuffer = mmio_map(0xB8000, 2 * 80 * 25);

    res = register_char_dev(
            &x64_platform_vga.char_dev,
            "vga-serial",
            &vga_serial_driver,
            NULL);
    if(res) {
        return res;
    }

    printk("Registered x64 Platform VGA Serial Device\n");
    return 0;
}
declare_init(device, x64_platform_vga_serial_register);
#endif

