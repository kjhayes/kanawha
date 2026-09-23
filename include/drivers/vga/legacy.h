#ifndef __KANAWHA__VGA_LEGACY_H__
#define __KANAWHA__VGA_LEGACY_H__

#include <kanawha/types.h>

#define LEGACY_VGA_RAW_WIDTH 80
#define LEGACY_VGA_RAW_HEIGHT 25

#define LEGACY_VGA_WIDTH 40
#define LEGACY_VGA_HEIGHT 50

#define LEGACY_VGA_ATTR_WHITE 0x7
#define LEGACY_VGA_ATTR_BLACK 0x0
#define LEGACY_VGA_ATTR_RED 0x4
#define LEGACY_VGA_ATTR_BLUE 0x1
#define LEGACY_VGA_ATTR_GREEN 0x2
#define LEGACY_VGA_ATTR_ORANGE (LEGACY_VGA_ATTR_RED | LEGACY_VGA_ATTR_GREEN)
#define LEGACY_VGA_ATTR_PURPLE (LEGACY_VGA_ATTR_RED | LEGACY_VGA_ATTR_BLUE)
#define LEGACY_VGA_ATTR_CYAN (LEGACY_VGA_ATTR_BLUE | LEGACY_VGA_ATTR_GREEN)

#define LEGACY_VGA_ATTR(__FG, __BG) \
    ((__FG)| ((__BG) << 4))

int
legacy_vga_setchar(
        uint8_t c,
        uint8_t attr,
        unsigned x,
        unsigned y);

uint8_t
legacy_vga_getchar(unsigned x, unsigned y);
uint8_t
legacy_vga_getattr(unsigned x, unsigned y);

void
legacy_vga_clear(
        uint8_t c,
        uint8_t attr);

void
legacy_vga_shift_up(
        uint8_t c,
        uint8_t attr);

void
legacy_vga_newline(
        uint8_t c,
        uint8_t attr);

void
legacy_vga_putchar(
        char c,
        uint8_t attr);

#endif
