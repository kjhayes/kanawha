
#include <kanawha/stdint.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>

#define X64_BOOT_VGA_FRAMEBUFFER_BASE 0xB8000

#define X64_BOOT_VGA_WIDTH  80
#define X64_BOOT_VGA_HEIGHT 25

#define X64_BOOT_VGA_ATTR_FG_WHITE 0x0F
#define X64_BOOT_VGA_ATTR_FG_ORANGE 0x06
#define X64_BOOT_VGA_ATTR_BG_BLACK 0x00

#define X64_BOOT_VGA_PRINTK_EARLY_ATTR (X64_BOOT_VGA_ATTR_FG_ORANGE | X64_BOOT_VGA_ATTR_BG_BLACK)

static unsigned x64_boot_vga_cursor_x = 0;
static unsigned x64_boot_vga_cursor_y = 0;

static inline uint16_t
x64_boot_vga_encode(uint8_t c, uint8_t attr) {
    return (((uint16_t)attr) << 8) | c;
}

static inline int
x64_boot_vga_setchar(uint8_t c, uint8_t attr, unsigned x, unsigned y) 
{
    if(x >= X64_BOOT_VGA_WIDTH) {
        return -EINVAL;
    }
    if(y >= X64_BOOT_VGA_HEIGHT) {
        return -EINVAL;
    }

    uint16_t *framebuffer = (void*)__va((uintptr_t)X64_BOOT_VGA_FRAMEBUFFER_BASE);
    framebuffer[x + (y * X64_BOOT_VGA_WIDTH)] = x64_boot_vga_encode(c, attr);

    return 0;
}

static void
x64_boot_vga_clear(uint8_t c, uint8_t attr) {
    for(unsigned y = 0; y < X64_BOOT_VGA_HEIGHT; y++) {
      for(unsigned x = 0; x < X64_BOOT_VGA_WIDTH; x++) {
          x64_boot_vga_setchar(c, attr, x, y);
      }
    }
}

static void
x64_boot_vga_shift_up(uint8_t c, uint8_t attr) 
{
    uint16_t *framebuffer = (void*)__va((uintptr_t)X64_BOOT_VGA_FRAMEBUFFER_BASE);

    for(unsigned y = 1; y < X64_BOOT_VGA_HEIGHT; y++) {
        for(unsigned x = 0; x < X64_BOOT_VGA_WIDTH; x++) {
            framebuffer[x + ((y-1) * X64_BOOT_VGA_WIDTH)] = framebuffer[x + (y * X64_BOOT_VGA_WIDTH)];
        }
    }

    for(unsigned x = 0; x < X64_BOOT_VGA_WIDTH; x++) {
        x64_boot_vga_setchar(c, attr, x, X64_BOOT_VGA_HEIGHT-1);
    }
}

static void x64_boot_vga_newline(uint8_t c, uint8_t attr) {
    x64_boot_vga_cursor_x = 0;
    x64_boot_vga_cursor_y += 1;
    if(x64_boot_vga_cursor_y >= X64_BOOT_VGA_HEIGHT) {
        x64_boot_vga_cursor_y = X64_BOOT_VGA_HEIGHT-1;
        x64_boot_vga_shift_up(c, attr);
    }
}

static void
x64_boot_vga_putchar(char c, uint8_t attr) 
{
    if(c == '\n') {
        x64_boot_vga_newline(' ', attr);
        return;
    } else if(c == '\r') {
        x64_boot_vga_cursor_x = 0;
        return;
    }
    else if(c == '\t') {
        unsigned tab_align = x64_boot_vga_cursor_x % 4;
        unsigned spaces = 4 - tab_align;
        while(spaces > 0) {
            x64_boot_vga_putchar(' ', attr);
            spaces--;
        }
        return;
    }

    if(x64_boot_vga_cursor_x >= X64_BOOT_VGA_WIDTH) {
        x64_boot_vga_newline(' ', attr);
    }

    x64_boot_vga_setchar(c, attr, x64_boot_vga_cursor_x, x64_boot_vga_cursor_y);
    x64_boot_vga_cursor_x++;
}

static void
x64_boot_vga_printk_early_handler(char c) {
    x64_boot_vga_putchar(c, X64_BOOT_VGA_PRINTK_EARLY_ATTR);
}

int x64_boot_vga_init(void) 
{
    int res;
    x64_boot_vga_clear(' ', X64_BOOT_VGA_PRINTK_EARLY_ATTR);
    res = printk_early_add_handler(x64_boot_vga_printk_early_handler);
    return res;
}

declare_init_desc(boot, x64_boot_vga_init, "Registering Boot VGA");

