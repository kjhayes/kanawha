#ifndef __KANAWHA__DRIVERS_VGA_H__
#define __KANAWHA__DRIVERS_VGA_H__

#include <kanawha/spinlock.h>
#include <kanawha/pio.h>
#include <kanawha/mmio.h>

#define VGA_GRAPHICS_ADDRESS_PORT 0x3CE
#define VGA_GRAPHICS_DATA_PORT    0x3CF

#define VGA_GRAPHICS_REG_SET_RESET        0x0
#define VGA_GRAPHICS_REG_ENABLE_SET_RESET 0x1
#define VGA_GRAPHICS_REG_COLOR_COMPARE    0x2
#define VGA_GRAPHICS_REG_DATA_ROTATE      0x3
#define VGA_GRAPHICS_REG_READ_MAP_SELECT  0x4
#define VGA_GRAPHICS_REG_GRAPHICS_MODE    0x5
#define VGA_GRAPHICS_REG_MISC_GRAPHICS    0x6
#define VGA_GRAPHICS_REG_COLOR_DONT_CARE  0x7
#define VGA_GRAPHICS_REG_BIT_MASK         0x8

#define VGA_SEQ_ADDRESS_PORT 0x3C4
#define VGA_SEQ_DATA_PORT    0x3C5

#define VGA_SEQ_REG_RESET                0x0
#define VGA_SEQ_REG_CLOCKING_MODE        0x1
#define VGA_SEQ_REG_MAP_MASK             0x2
#define VGA_SEQ_REG_CHARACTER_MAP_SELECT 0x3
#define VGA_SEQ_REG_SEQ_MEMORY_MODE      0x4

#define VGA_CRT_ADDRESS_PORT  0x3D4
#define VGA_CRT_DATA_PORT     0x3D5

#define VGA_CRT_REG_HORIZONTAL_TOTAL          0x00
#define VGA_CRT_REG_END_HORIZONTAL_DISPLAY    0x01
#define VGA_CRT_REG_START_HORIZONTAL_BLANKING 0x02
#define VGA_CRT_REG_END_HORIZONTAL_BLANKING   0x03
#define VGA_CRT_REG_START_HORIZONTAL_RETRACE  0x04
#define VGA_CRT_REG_END_HORIZONTAL_RETRACE    0x05
#define VGA_CRT_REG_VERTICAL_TOTAL            0x06
#define VGA_CRT_REG_OVERFLOW                  0x07
#define VGA_CRT_REG_PRESET_ROW_SCAN           0x08
#define VGA_CRT_REG_MAXIMUM_SCAN_LINE         0x09
#define VGA_CRT_REG_CURSOR_START              0x0A
#define VGA_CRT_REG_CURSOR_END                0x0B
#define VGA_CRT_REG_START_ADDRESS_HIGH        0x0C
#define VGA_CRT_REG_START_ADDRESS_LOW         0x0D
#define VGA_CRT_REG_CURSOR_LOCATION_HIGH      0x0E
#define VGA_CRT_REG_CURSOR_LOCATION_LOW       0x0F
#define VGA_CRT_REG_START_VERTICAL_RETRACE    0x10
#define VGA_CRT_REG_END_VERTICAL_RETRACE      0x11
#define VGA_CRT_REG_END_VERTICAL_DISPLAY      0x12
#define VGA_CRT_REG_OFFSET                    0x13
#define VGA_CRT_REG_UNDERLINE_LOCATION        0x14
#define VGA_CRT_REG_START_VERTICAL_BLANKING   0x15
#define VGA_CRT_REG_END_VERTICAL_BLANKING     0x16
#define VGA_CRT_REG_CRTC_MODE_CONTROL         0x17
#define VGA_CRT_REG_LINE_COMPARE              0x18

#define VGA_ATTRIBUTE_ADDR_DATA_PORT 0x3C0
#define VGA_ATTRIBUTE_DATA_READ_PORT 0x3C1

#define VGA_ATTRIBUTE_REG_PALETTE_BASE             0x00
#define VGA_ATTRIBUTE_REG_PALETTE_0  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x0)
#define VGA_ATTRIBUTE_REG_PALETTE_1  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x1)
#define VGA_ATTRIBUTE_REG_PALETTE_2  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x2)
#define VGA_ATTRIBUTE_REG_PALETTE_3  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x3)
#define VGA_ATTRIBUTE_REG_PALETTE_4  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x4)
#define VGA_ATTRIBUTE_REG_PALETTE_5  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x5)
#define VGA_ATTRIBUTE_REG_PALETTE_6  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x6)
#define VGA_ATTRIBUTE_REG_PALETTE_7  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x7)
#define VGA_ATTRIBUTE_REG_PALETTE_8  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x8)
#define VGA_ATTRIBUTE_REG_PALETTE_9  (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0x9)
#define VGA_ATTRIBUTE_REG_PALETTE_10 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xA)
#define VGA_ATTRIBUTE_REG_PALETTE_11 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xB)
#define VGA_ATTRIBUTE_REG_PALETTE_12 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xC)
#define VGA_ATTRIBUTE_REG_PALETTE_13 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xD)
#define VGA_ATTRIBUTE_REG_PALETTE_14 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xE)
#define VGA_ATTRIBUTE_REG_PALETTE_15 (VGA_ATTRIBUTE_REG_PALETTE_BASE + 0xF)
#define VGA_ATTRIBUTE_REG_MODE_CONTROL             0x10
#define VGA_ATTRIBUTE_REG_OVERSCAN_COLOR           0x11
#define VGA_ATTRIBUTE_REG_COLOR_PLANE_ENABLE       0x12
#define VGA_ATTRIBUTE_REG_HORIZONTAL_PIXEL_PANNING 0x13
#define VGA_ATTRIBUTE_REG_COLOR_SELECT             0x14

#define VGA_INPUT_STATUS_0_PORT 0x3C2
#define VGA_INPUT_STATUS_1_PORT 0x3DA

#define VGA_MISC_OUTPUT_READ_PORT  0x3CC
#define VGA_MISC_OUTPUT_WRITE_PORT 0x3C2

#define VGA_DAC_ADDRESS_READ_MODE_PORT  0x3C7
#define VGA_DAC_ADDRESS_WRITE_MODE_PORT 0x3C8
#define VGA_DAC_DATA_PORT               0x3C9
#define VGA_DAC_STATE_PORT              0x3C7

struct vga_ports {
    pio_t graphics_addr;
    pio_t graphics_data;
    pio_t seq_addr;
    pio_t seq_data;
    pio_t crt_addr;
    pio_t crt_data;
    pio_t attribute_addr_data;
    pio_t attribute_data_read;
    pio_t input_status_0;
    pio_t input_status_1;
    pio_t misc_output_read;
    pio_t misc_output_write;
    pio_t dac_address_read_mode;
    pio_t dac_address_write_mode;
    pio_t dac_data;
    pio_t dac_state;
};

extern struct vga_ports default_vga_ports;

struct vga_dev
{
    struct vga_ports *ports;

    spinlock_t graphics_lock;
    uint8_t graphics_index;

    spinlock_t seq_lock;
    uint8_t seq_index;

    spinlock_t crt_lock;
    uint8_t crt_index;

    spinlock_t attribute_lock;

    spinlock_t dac_lock;

    spinlock_t mode_lock;
    uint8_t write_mode : 2;
    uint8_t read_mode : 1;
    uint8_t alphanumeric : 1;
};

int
vga_dev_init(
        struct vga_dev *dev,
        struct vga_ports *ports);

uint8_t
vga_read_graphics_reg(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_graphics_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);
void
vga_modify_graphics_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask);

uint8_t
vga_read_seq_reg(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_seq_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);
void
vga_modify_seq_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask);

uint8_t
vga_read_crt_reg(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_crt_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);
void
vga_modify_crt_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask);

uint8_t
vga_read_attribute_reg(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_attribute_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);
void
vga_modify_attribute_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask);

static inline uint8_t
vga_read_misc_output_reg(
        struct vga_dev *dev)
{
    return inb(dev->ports->misc_output_read);
}

static inline void
vga_write_misc_output_reg(
        struct vga_dev *dev,
        uint8_t value)
{
    outb(dev->ports->misc_output_write, value);
}

void
vga_lock_crt_reg(
        struct vga_dev *dev);
void
vga_unlock_crt_reg(
        struct vga_dev *dev);

int
vga_set_write_mode(
        struct vga_dev *dev,
        uint8_t mode);
uint8_t
vga_get_write_mode(
        struct vga_dev *dev);

int
vga_set_read_mode(
        struct vga_dev *dev,
        uint8_t mode);
uint8_t
vga_get_read_mode(
        struct vga_dev *dev);

void
vga_set_alphanumeric(
        struct vga_dev *dev,
        uint8_t value);
uint8_t
vga_get_alphanumeric(
        struct vga_dev *dev);

void
vga_screen_disable(
        struct vga_dev *dev);
void
vga_screen_enable(
        struct vga_dev *dev);

void
vga_set_write_planes(
        struct vga_dev *dev,
        uint8_t plane_mask);

void vga_set_color_planes(
        struct vga_dev *dev,
        uint8_t plane_mask);

void
vga_enable_planar(
        struct vga_dev *dev);
void
vga_enable_linear(
        struct vga_dev *dev);

void
vga_set_color_mode_pop_1(
        struct vga_dev *dev);
void
vga_set_color_mode_pop_2(
        struct vga_dev *dev);
void
vga_set_color_mode_pop_4(
        struct vga_dev *dev);

void
vga_enable_8_bit_color(
        struct vga_dev *dev);
void
vga_disable_8_bit_color(
        struct vga_dev *dev);

void
vga_set_horizontal_panning(
        struct vga_dev *dev,
        uint8_t panning);

void
vga_disable_even_odd(
        struct vga_dev *dev);
void
vga_enable_even_odd(
        struct vga_dev *dev);

void
vga_enable_8_dot_mode(
        struct vga_dev *dev);
void
vga_enable_9_dot_mode(
        struct vga_dev *dev);

uint8_t
vga_get_dots_per_character(
        struct vga_dev *dev);

void
vga_enable_half_rate_dot_clock(
        struct vga_dev *dev);
void
vga_disable_half_rate_dot_clock(
        struct vga_dev *dev);

void
vga_crt_set_horizontal_total(
        struct vga_dev *dev,
        uint16_t characters);
uint16_t
vga_crt_get_horizontal_total(
        struct vga_dev *dev);

void
vga_crt_set_horizontal_display_end(
        struct vga_dev *dev,
        uint16_t characters);

void
vga_crt_set_horizontal_blanking_start(
        struct vga_dev *dev,
        uint16_t characters);

void
vga_crt_set_horizontal_blanking_end(
        struct vga_dev *dev,
        uint16_t characters);

void
vga_crt_set_vertical_total(
        struct vga_dev *dev,
        uint16_t scanlines);
uint16_t
vga_crt_get_vertical_total(
        struct vga_dev *dev);

void
vga_crt_set_vertical_display_end(
        struct vga_dev *dev,
        uint16_t scanlines);

void
vga_crt_set_vertical_blanking_start(
        struct vga_dev *dev,
        uint16_t scanline);
void
vga_crt_set_vertical_blanking_end(
        struct vga_dev *dev,
        uint16_t scanline);

void
vga_crt_set_maximum_scanline(
        struct vga_dev *dev,
        uint8_t value);

void
vga_crt_set_scanline_offset(
        struct vga_dev *dev,
        uint16_t offset);

void
vga_crt_set_address_size(
        struct vga_dev *dev,
        uint8_t size);

void
vga_dac_set_color(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t r,
        uint8_t g,
        uint8_t b);

void
vga_crt_disable_retrace(
        struct vga_dev *dev);

void
vga_crt_enable_scan_doubling(
        struct vga_dev *dev);
void
vga_crt_disable_scan_doubling(
        struct vga_dev *dev);

#endif
