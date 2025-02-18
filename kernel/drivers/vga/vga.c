
#include <drivers/vga/vga.h>
#include <kanawha/pio.h>

struct vga_ports default_vga_ports = {
    .graphics_data = VGA_GRAPHICS_DATA_PORT,
    .graphics_addr = VGA_GRAPHICS_ADDRESS_PORT,
    .seq_data = VGA_SEQ_DATA_PORT,
    .seq_addr = VGA_SEQ_ADDRESS_PORT,
    .crt_data = VGA_CRT_DATA_PORT,
    .crt_addr = VGA_CRT_ADDRESS_PORT,
    .attribute_data_read = VGA_ATTRIBUTE_DATA_READ_PORT,
    .attribute_addr_data = VGA_ATTRIBUTE_ADDR_DATA_PORT,
    .input_status_0 = VGA_INPUT_STATUS_0_PORT,
    .input_status_1 = VGA_INPUT_STATUS_1_PORT,
    .misc_output_read = VGA_MISC_OUTPUT_READ_PORT,
    .misc_output_write = VGA_MISC_OUTPUT_WRITE_PORT,
    .dac_address_read_mode = VGA_DAC_ADDRESS_READ_MODE_PORT,
    .dac_address_write_mode = VGA_DAC_ADDRESS_WRITE_MODE_PORT,
    .dac_data = VGA_DAC_DATA_PORT,
    .dac_state = VGA_DAC_STATE_PORT,
};

int
vga_dev_init(
        struct vga_dev *dev,
        struct vga_ports *ports)
{
    dev->ports = ports; 

    spinlock_init(&dev->dac_lock);

    spinlock_init(&dev->graphics_lock);
    dev->graphics_index = inb(ports->graphics_addr);

    spinlock_init(&dev->seq_lock);
    dev->seq_index = inb(ports->seq_addr);

    spinlock_init(&dev->crt_lock);
    dev->crt_index = inb(ports->crt_addr);

    // Color Mode
    vga_write_misc_output_reg(
            dev,
            vga_read_misc_output_reg(dev) | 0x1);

    spinlock_init(&dev->attribute_lock);
    // Make sure that the attribute address/data register expects an address next
    inb(dev->ports->input_status_1);

    // Get the current memory mode info
    spinlock_init(&dev->mode_lock);

    uint8_t graphics_mode_reg =
        vga_read_graphics_reg(dev, VGA_GRAPHICS_REG_GRAPHICS_MODE);
    dev->write_mode = graphics_mode_reg & 0b11;
    dev->read_mode = (graphics_mode_reg >> 3) & 0b1;

    uint8_t misc_graphics_reg =
        vga_read_graphics_reg(dev, VGA_GRAPHICS_REG_MISC_GRAPHICS);
    dev->alphanumeric = (misc_graphics_reg >> 0) & 1;

    // Set memory map to the 0xA0000-0xAFFFF 64K region
    vga_screen_disable(dev);
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_MISC_GRAPHICS,
            0b01<<2,
            0b11<<2);
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_START_ADDRESS_LOW,
            0);
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_START_ADDRESS_HIGH,
            0);
    vga_screen_enable(dev);

    return 0;
}

uint8_t
vga_read_graphics_reg(
        struct vga_dev *dev,
        uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->graphics_lock);

    if(dev->graphics_index != index) {
        outb(dev->ports->graphics_addr, index);
        dev->graphics_index = index;
    }
    value = inb(dev->ports->graphics_data);

    spin_unlock(&dev->graphics_lock);
    return value;
}
void
vga_write_graphics_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value)
{
    spin_lock(&dev->graphics_lock);

    if(dev->graphics_index != index) {
        outb(dev->ports->graphics_addr, index);
        dev->graphics_index = index;
    }
    outb(dev->ports->graphics_data, value);

    spin_unlock(&dev->graphics_lock);
}

void
vga_modify_graphics_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask)
{
    spin_lock(&dev->graphics_lock);

    if(dev->graphics_index != index) {
        outb(dev->ports->graphics_addr, index);
        dev->graphics_index = index;
    }
    uint8_t old_value;
    old_value = inb(dev->ports->graphics_data);
    old_value &= ~mask;
    old_value |= (value & mask);
    outb(dev->ports->graphics_data, old_value);

    spin_unlock(&dev->graphics_lock);
}

uint8_t
vga_read_seq_reg(
        struct vga_dev *dev,
        uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->seq_lock);

    if(dev->seq_index != index) {
        outb(dev->ports->seq_addr, index);
        dev->seq_index = index;
    }
    value = inb(dev->ports->seq_data);

    spin_unlock(&dev->seq_lock);
    return value;
}
void
vga_write_seq_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value)
{
    spin_lock(&dev->seq_lock);

    if(dev->seq_index != index) {
        outb(dev->ports->seq_addr, index);
        dev->seq_index = index;
    }
    outb(dev->ports->seq_data, value);

    spin_unlock(&dev->seq_lock);
}
void
vga_modify_seq_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask)
{
    spin_lock(&dev->seq_lock);

    if(dev->seq_index != index) {
        outb(dev->ports->seq_addr, index);
        dev->seq_index = index;
    }
    uint8_t old_value;
    old_value = inb(dev->ports->seq_data);
    old_value &= ~mask;
    old_value |= value & mask;
    outb(dev->ports->seq_data, old_value);

    spin_unlock(&dev->seq_lock);
}

uint8_t
vga_read_crt_reg(
        struct vga_dev *dev,
        uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->crt_lock);

    if(dev->crt_index != index) {
        outb(dev->ports->crt_addr, index);
        dev->crt_index = index;
    }
    value = inb(dev->ports->crt_data);

    spin_unlock(&dev->crt_lock);
    return value;
}
void
vga_write_crt_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value)
{
    spin_lock(&dev->crt_lock);

    if(dev->crt_index != index) {
        outb(dev->ports->crt_addr, index);
        dev->crt_index = index;
    }
    outb(dev->ports->crt_data, value);

    spin_unlock(&dev->crt_lock);
}
void
vga_modify_crt_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask)
{
    spin_lock(&dev->crt_lock);

    if(dev->crt_index != index) {
        outb(dev->ports->crt_addr, index);
        dev->crt_index = index;
    }
    uint8_t old_value;
    old_value = inb(dev->ports->crt_data);
    old_value &= ~mask;
    old_value |= value & mask;
    outb(dev->ports->crt_data, old_value);

    spin_unlock(&dev->crt_lock);
}

uint8_t
vga_read_attribute_reg(
        struct vga_dev *dev,
        uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->attribute_lock);

    inb(dev->ports->input_status_1); // Reset back to waiting for index without writing
    outb(dev->ports->attribute_addr_data, (1ULL<<5) | index);
    value = inb(dev->ports->attribute_data_read);

    spin_unlock(&dev->attribute_lock);
    return value;
}
void
vga_write_attribute_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value)
{
    spin_lock(&dev->attribute_lock);

    inb(dev->ports->input_status_1);
    outb(dev->ports->attribute_addr_data, (1ULL<<5) | index);
    outb(dev->ports->attribute_addr_data, value);

    spin_unlock(&dev->attribute_lock);
}
void
vga_modify_attribute_reg(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value,
        uint8_t mask)
{
    spin_lock(&dev->attribute_lock);

    uint8_t old_value;

    inb(dev->ports->input_status_1);

    outb(dev->ports->attribute_addr_data, (1ULL<<5) | index);
    old_value = inb(dev->ports->attribute_data_read);

    old_value &= ~mask;
    old_value |= value & mask;

    outb(dev->ports->attribute_addr_data, value);

    spin_unlock(&dev->attribute_lock);
}

void
vga_lock_crt_reg(struct vga_dev *dev)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_END_VERTICAL_RETRACE,
            1<<7,
            1<<7);
} 
void
vga_unlock_crt_reg(struct vga_dev *dev)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_END_VERTICAL_RETRACE,
            0,
            1<<7);
}

int
vga_set_write_mode(
        struct vga_dev *dev,
        uint8_t mode)
{
    spin_lock(&dev->mode_lock);

    if(dev->write_mode == mode) {
        spin_unlock(&dev->mode_lock);
        return 0;
    }

    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            mode,
            0b11);
    dev->write_mode = mode;

    spin_unlock(&dev->mode_lock);
    return 0;
}
uint8_t
vga_get_write_mode(
        struct vga_dev *dev)
{
    return dev->write_mode;
}

int
vga_set_read_mode(
        struct vga_dev *dev,
        uint8_t mode)
{
    spin_lock(&dev->mode_lock);

    if(dev->read_mode == mode) {
        spin_unlock(&dev->mode_lock);
        return 0;
    }

    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            (mode & 1) << 3,
            1 << 3);
    dev->read_mode = mode;

    spin_unlock(&dev->mode_lock);
    return 0;
}
uint8_t
vga_get_read_mode(
        struct vga_dev *dev)
{
    return dev->read_mode;
}

void
vga_set_alphanumeric(
        struct vga_dev *dev,
        uint8_t value)
{
    spin_lock(&dev->mode_lock);

    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_MISC_GRAPHICS,
            (!value) & 0b1,
            0b1);
    dev->alphanumeric = value & 0b1;

    spin_unlock(&dev->mode_lock);
}

uint8_t
vga_get_alphanumeric(
        struct vga_dev *dev)
{
    return dev->alphanumeric;
}

void
vga_screen_disable(struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            1<<5,
            1<<5);
}
void
vga_screen_enable(struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            0,
            1<<5);
}

void
vga_set_write_planes(
        struct vga_dev *dev,
        uint8_t plane_mask)
{
    vga_write_seq_reg(
            dev,
            VGA_SEQ_REG_MAP_MASK,
            plane_mask & 0xF);
}

void
vga_set_color_planes(
        struct vga_dev *dev,
        uint8_t plane_mask)
{
    vga_write_attribute_reg(
            dev,
            VGA_ATTRIBUTE_REG_COLOR_PLANE_ENABLE,
            plane_mask);
}

void
vga_enable_planar(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_SEQ_MEMORY_MODE,
            0,
            1<<3);
}
void
vga_enable_linear(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_SEQ_MEMORY_MODE,
            1<<3,
            1<<3);
}

void
vga_set_color_mode_pop_1(
        struct vga_dev *dev)
{
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            0b00<<5,
            0b11<<5);
}
void
vga_set_color_mode_pop_2(
        struct vga_dev *dev)
{
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            0b01<<5,
            0b11<<5);
}
void
vga_set_color_mode_pop_4(
        struct vga_dev *dev)
{
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            0b10<<5,
            0b11<<5);
}

void
vga_enable_8_bit_color(
        struct vga_dev *dev)
{
    vga_modify_attribute_reg(
            dev,
            VGA_ATTRIBUTE_REG_MODE_CONTROL,
            1<<6,
            1<<6);
}
void
vga_disable_8_bit_color(
        struct vga_dev *dev)
{
    vga_modify_attribute_reg(
            dev,
            VGA_ATTRIBUTE_REG_MODE_CONTROL,
            0,
            1<<6);
}

void
vga_set_horizontal_panning(
        struct vga_dev *dev,
        uint8_t panning)
{
    vga_write_attribute_reg(
            dev,
            VGA_ATTRIBUTE_REG_HORIZONTAL_PIXEL_PANNING,
            panning & 0xF);
}

void
vga_disable_even_odd(
        struct vga_dev *dev)
{
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            0,
            1<<4);
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_SEQ_MEMORY_MODE,
            1<<2,
            1<<2);
}
void
vga_enable_even_odd(
        struct vga_dev *dev)
{
    vga_modify_graphics_reg(
            dev,
            VGA_GRAPHICS_REG_GRAPHICS_MODE,
            1<<4,
            1<<4);
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_SEQ_MEMORY_MODE,
            0,
            1<<2);
}

void
vga_enable_8_dot_mode(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            1,
            1);
}
void
vga_enable_9_dot_mode(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            0,
            1);
}

uint8_t
vga_get_dots_per_character(
        struct vga_dev *dev)
{
    uint8_t clock_mode = vga_read_seq_reg(dev, VGA_SEQ_REG_CLOCKING_MODE);
    return (clock_mode & 1) ? 8 : 9;
}

void
vga_enable_half_rate_dot_clock(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            1<<3,
            1<<3);
}
void
vga_disable_half_rate_dot_clock(
        struct vga_dev *dev)
{
    vga_modify_seq_reg(
            dev,
            VGA_SEQ_REG_CLOCKING_MODE,
            0,
            1<<3);
}

void
vga_crt_set_horizontal_total(
        struct vga_dev *dev,
        uint16_t characters)
{
    if(characters > 5) {
        characters -= 5;
    } else {
        characters = 0;
    }
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_HORIZONTAL_TOTAL,
            characters & 0xFF);
}
uint16_t
vga_crt_get_horizontal_total(
        struct vga_dev *dev)
{
    return vga_read_crt_reg(
            dev,
            VGA_CRT_REG_HORIZONTAL_TOTAL);
}

void
vga_crt_set_horizontal_display_end(
        struct vga_dev *dev,
        uint16_t characters)
{
    if(characters > 0) {
        characters--;
    }
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_END_HORIZONTAL_DISPLAY,
            characters & 0xFF);
}

void
vga_crt_set_horizontal_blanking_start(
        struct vga_dev *dev,
        uint16_t characters)
{
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_START_HORIZONTAL_BLANKING,
            characters & 0xFF);
}

void
vga_crt_set_horizontal_blanking_end(
        struct vga_dev *dev,
        uint16_t characters)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_END_HORIZONTAL_BLANKING,
            characters & 0x1F,
            0x1F);
}

void
vga_crt_set_vertical_total(
        struct vga_dev *dev,
        uint16_t scanlines)
{
    uint8_t low_bits = scanlines & 0xFF;
    uint8_t bit8 = (scanlines >> 8) & 0b1;
    uint8_t bit9 = (scanlines >> 9) & 0b1;

    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_VERTICAL_TOTAL,
            low_bits);
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_OVERFLOW,
            (bit8 << 0) | (bit9 << 5),
            (1<<0) | (1<<5));
}
uint16_t
vga_crt_get_vertical_total(
        struct vga_dev *dev)
{
    uint8_t low_bits = vga_read_crt_reg(dev, VGA_CRT_REG_VERTICAL_TOTAL);
    uint8_t overflow = vga_read_crt_reg(dev, VGA_CRT_REG_OVERFLOW);
    uint16_t value = low_bits
        | ((uint16_t)((overflow >> 0) & 0b1) << 8)
        | ((uint16_t)((overflow >> 5) & 0b1) << 9);
    return value;
}

void
vga_crt_set_vertical_display_end(
        struct vga_dev *dev,
        uint16_t scanlines)
{
    uint8_t low_bits = scanlines & 0xFF;
    uint8_t bit8 = (scanlines >> 8) & 0b1;
    uint8_t bit9 = (scanlines >> 9) & 0b1;

    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_END_VERTICAL_DISPLAY,
            low_bits);
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_OVERFLOW,
            (bit8 << 1) | (bit9 << 6),
            (1<<1) | (1<<6));
}

void
vga_crt_set_vertical_blanking_start(
        struct vga_dev *dev,
        uint16_t scanlines)
{
    uint8_t low_bits = scanlines & 0xFF;
    uint8_t bit8 = (scanlines >> 8) & 0b1;
    uint8_t bit9 = (scanlines >> 9) & 0b1;

    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_START_VERTICAL_BLANKING,
            low_bits);
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_OVERFLOW,
            bit8 << 3,
            1<<3);
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_MAXIMUM_SCAN_LINE,
            bit9<<5,
            1<<5);
}

void
vga_crt_set_vertical_blanking_end(
        struct vga_dev *dev,
        uint16_t scanlines)
{
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_END_VERTICAL_BLANKING,
            scanlines & 0x7F);
}

void
vga_crt_set_maximum_scanline(
        struct vga_dev *dev,
        uint8_t value)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_MAXIMUM_SCAN_LINE,
            value & 0x1F,
            0x1F);
}

void
vga_crt_set_scanline_offset(
        struct vga_dev *dev,
        uint16_t offset)
{
    vga_write_crt_reg(
            dev,
            VGA_CRT_REG_OFFSET,
            (uint8_t)(offset / 2));
}

void
vga_crt_set_address_size(
        struct vga_dev *dev,
        uint8_t size)
{
    int byte_enabled;
    int dword_enabled;
    switch(size) {
        case 1:
            byte_enabled = 1;
            dword_enabled = 0;
            break;
        case 2:
            byte_enabled = 0;
            dword_enabled = 0;
            break;
        case 4:
            dword_enabled = 1;
            byte_enabled = 0;
            break;
        default: // default to byte addresses
            byte_enabled = 1;
            dword_enabled = 0;
            wprintk("Driver tried to set VGA CRT address size to 0x%x! (defaulting to byte addressing)\n",
                    size);
            break;
    }

    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_UNDERLINE_LOCATION,
            (dword_enabled << 6),
            1<<6);
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_CRTC_MODE_CONTROL,
            (byte_enabled << 6),
            1<<6);
}

void
vga_dac_set_color(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t r,
        uint8_t g,
        uint8_t b)
{
    spin_lock(&dev->dac_lock);

    outb(dev->ports->dac_address_write_mode, index);
    outb(dev->ports->dac_data, r & 0x3F);
    outb(dev->ports->dac_data, g & 0x3F);
    outb(dev->ports->dac_data, b & 0x3F);

    spin_unlock(&dev->dac_lock);
}

void
vga_crt_disable_retrace(
        struct vga_dev *dev)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_CRTC_MODE_CONTROL,
            0,
            1<<7);
}

void
vga_crt_enable_scan_doubling(
        struct vga_dev *dev)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_MAXIMUM_SCAN_LINE,
            1<<7,
            1<<7);
}

void
vga_crt_disable_scan_doubling(
        struct vga_dev *dev)
{
    vga_modify_crt_reg(
            dev,
            VGA_CRT_REG_MAXIMUM_SCAN_LINE,
            0,
            1<<7);
}

