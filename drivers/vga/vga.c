
#include <drivers/vga/vga.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/pio.h>

static int
vga_dev_init(struct vga_dev *dev)
{
    spinlock_init(&dev->dac_lock);
    dev->dac_order = VGA_DAC_ORDER_RGB;

    spinlock_init(&dev->graphics_lock);
    dev->graphics_index = vga_read_register(dev, GraphicsControllerAddress);

    spinlock_init(&dev->seq_lock);
    dev->seq_index = vga_read_register(dev, SequencerAddress);

    spinlock_init(&dev->crt_lock);
    dev->crt_index = vga_read_register(dev, CRTCControllerAddress);

    vga_write_field(dev, InputOutputAddressSelect, 1);

    spinlock_init(&dev->attribute_lock);
    // Make sure that the attribute address/data register expects an address
    // next
    vga_read_register(dev, InputStatus1);

    // Set memory map to the 0xA0000-0xAFFFF 64K region
    vga_screen_disable(dev);

    vga_write_field(dev, MemoryMapSelect, 1);
    vga_write_field(dev, StartAddress, 0x0);

    vga_screen_enable(dev);

    return 0;
}

static int
vga_dev_deinit(struct vga_dev *dev)
{
    vga_screen_disable(dev);
    return 0;
}

DEFINE_REGISTRY(vga_dev, registry_node, vga_dev_init, vga_dev_deinit);

uint8_t
vga_read_graphics_register_set(struct vga_dev *dev, uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->graphics_lock);

    if(dev->graphics_index != index)
    {
        vga_write_register(dev, GraphicsControllerAddress, index);
        dev->graphics_index = index;
    }
    value = vga_read_register(dev, GraphicsControllerData);

    spin_unlock(&dev->graphics_lock);
    return value;
}
void
vga_write_graphics_register_set(struct vga_dev *dev,
                                uint8_t index,
                                uint8_t value)
{
    spin_lock(&dev->graphics_lock);

    if(dev->graphics_index != index)
    {
        vga_write_register(dev, GraphicsControllerAddress, index);
        dev->graphics_index = index;
    }
    vga_write_register(dev, GraphicsControllerData, value);

    spin_unlock(&dev->graphics_lock);
}

uint8_t
vga_read_sequencer_register_set(struct vga_dev *dev, uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->seq_lock);

    if(dev->seq_index != index)
    {
        vga_write_register(dev, SequencerAddress, index);
        dev->seq_index = index;
    }
    value = vga_read_register(dev, SequencerData);

    spin_unlock(&dev->seq_lock);
    return value;
}
void
vga_write_sequencer_register_set(struct vga_dev *dev,
                                 uint8_t index,
                                 uint8_t value)
{
    spin_lock(&dev->seq_lock);

    if(dev->seq_index != index)
    {
        vga_write_register(dev, SequencerAddress, index);
        dev->seq_index = index;
    }
    vga_write_register(dev, SequencerData, value);

    spin_unlock(&dev->seq_lock);
}

uint8_t
vga_read_crt_register_set(struct vga_dev *dev, uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->crt_lock);

    if(dev->crt_index != index)
    {
        vga_write_register(dev, CRTCControllerAddress, index);
        dev->crt_index = index;
    }
    value = vga_read_register(dev, CRTCControllerData);

    spin_unlock(&dev->crt_lock);
    return value;
}
void
vga_write_crt_register_set(struct vga_dev *dev, uint8_t index, uint8_t value)
{
    spin_lock(&dev->crt_lock);

    if(dev->crt_index != index)
    {
        vga_write_register(dev, CRTCControllerAddress, index);
        dev->crt_index = index;
    }
    vga_write_register(dev, CRTCControllerData, value);

    spin_unlock(&dev->crt_lock);
}

uint8_t
vga_read_attribute_register_set(struct vga_dev *dev, uint8_t index)
{
    uint8_t value;
    spin_lock(&dev->attribute_lock);

    vga_read_register(
        dev,
        InputStatus1); // Reset back to waiting for index without writing
    vga_write_register(dev, AttributeAddressData, (1ULL << 5) | index);
    value = vga_read_register(dev, AttributeDataRead);

    spin_unlock(&dev->attribute_lock);
    return value;
}
void
vga_write_attribute_register_set(struct vga_dev *dev,
                                 uint8_t index,
                                 uint8_t value)
{
    spin_lock(&dev->attribute_lock);

    vga_read_register(
        dev,
        InputStatus1); // Reset back to waiting for index without writing
    vga_write_register(dev, AttributeAddressData, (1ULL << 5) | index);
    vga_write_register(dev, AttributeAddressData, value);

    spin_unlock(&dev->attribute_lock);
}

void
vga_lock_crt_reg(struct vga_dev *dev)
{
    vga_write_field(dev, CRTCRegistersProtectEnable, 1);
}
void
vga_unlock_crt_reg(struct vga_dev *dev)
{
    vga_write_field(dev, CRTCRegistersProtectEnable, 0);
}

void
vga_screen_disable(struct vga_dev *dev)
{
    vga_write_field(dev, ScreenDisable, 1);
}

void
vga_screen_enable(struct vga_dev *dev)
{
    vga_write_field(dev, ScreenDisable, 0);
}

void
vga_set_write_planes(struct vga_dev *dev, uint8_t plane_mask)
{
    vga_write_field(dev, MemoryPlaneWriteEnable, plane_mask);
}

void
vga_set_color_planes(struct vga_dev *dev, uint8_t plane_mask)
{
    vga_write_field(dev, ColorPlaneEnable, plane_mask);
}

void
vga_enable_planar(struct vga_dev *dev)
{
    vga_write_field(dev, Chain4Enable, 0);
}
void
vga_enable_linear(struct vga_dev *dev)
{
    vga_write_field(dev, Chain4Enable, 1);
}

void
vga_set_color_mode_pop_1(struct vga_dev *dev)
{
    vga_write_field(dev, ShiftRegisterInterleaveMode, 0);
    vga_write_field(dev, ColorShiftMode_256, 0);
}
void
vga_set_color_mode_pop_2(struct vga_dev *dev)
{
    vga_write_field(dev, ShiftRegisterInterleaveMode, 1);
    vga_write_field(dev, ColorShiftMode_256, 0);
}
void
vga_set_color_mode_pop_4(struct vga_dev *dev)
{
    vga_write_field(dev, ShiftRegisterInterleaveMode, 0);
    vga_write_field(dev, ColorShiftMode_256, 1);
}

void
vga_enable_8_bit_color(struct vga_dev *dev)
{
    vga_write_field(dev, ColorEnable_8Bit, 1);
}
void
vga_disable_8_bit_color(struct vga_dev *dev)
{
    vga_write_field(dev, ColorEnable_8Bit, 0);
}

void
vga_set_horizontal_panning(struct vga_dev *dev, uint8_t panning)
{
    vga_write_field(dev, PixelShiftCount, panning);
}

void
vga_disable_even_odd(struct vga_dev *dev)
{
    vga_write_field(dev, HostOddEvenMemoryReadAddressingEnable, 0);
    vga_write_field(dev, HostOddEvenMemoryWriteAddressingDisable, 1);
}
void
vga_enable_even_odd(struct vga_dev *dev)
{
    vga_write_field(dev, HostOddEvenMemoryReadAddressingEnable, 1);
    vga_write_field(dev, HostOddEvenMemoryWriteAddressingDisable, 0);
}

void
vga_enable_8_dot_mode(struct vga_dev *dev)
{
    vga_write_field(dev, DotMode_9_8, 1);
}
void
vga_enable_9_dot_mode(struct vga_dev *dev)
{
    vga_write_field(dev, DotMode_9_8, 0);
}

uint8_t
vga_get_dots_per_character(struct vga_dev *dev)
{
    return vga_read_field(dev, DotMode_9_8) ? 8 : 9;
}

void
vga_enable_half_rate_dot_clock(struct vga_dev *dev)
{
    vga_write_field(dev, DotClockRate, 1);
}
void
vga_disable_half_rate_dot_clock(struct vga_dev *dev)
{
    vga_write_field(dev, DotClockRate, 0);
}

void
vga_crt_set_horizontal_total(struct vga_dev *dev, uint16_t characters)
{
    if(characters > 5)
    {
        characters -= 5;
    }
    else
    {
        characters = 0;
    }
    vga_write_field(dev, HorizontalTotal, characters);
}
uint16_t
vga_crt_get_horizontal_total(struct vga_dev *dev)
{
    return vga_read_field(dev, HorizontalTotal);
}

void
vga_crt_set_horizontal_display_end(struct vga_dev *dev, uint16_t characters)
{
    if(characters > 0)
    {
        characters--;
    }
    vga_write_field(dev, EndHorizontalDisplay, characters);
}

void
vga_crt_set_horizontal_blanking_start(struct vga_dev *dev, uint16_t characters)
{
    vga_write_field(dev, StartHorizontalBlanking, characters);
}

void
vga_crt_set_horizontal_blanking_end(struct vga_dev *dev, uint16_t characters)
{
    vga_write_field(dev, EndHorizontalBlanking, characters);
}

void
vga_crt_set_vertical_total(struct vga_dev *dev, uint16_t scanlines)
{
    vga_write_field(dev, VerticalTotal, scanlines);
}
uint16_t
vga_crt_get_vertical_total(struct vga_dev *dev)
{
    return vga_read_field(dev, VerticalTotal);
}

void
vga_crt_set_vertical_display_end(struct vga_dev *dev, uint16_t scanlines)
{
    vga_write_field(dev, VerticalDisplayEnd, scanlines);
}

void
vga_crt_set_vertical_blanking_start(struct vga_dev *dev, uint16_t scanlines)
{
    vga_write_field(dev, StartVerticalBlanking, scanlines);
}

void
vga_crt_set_vertical_blanking_end(struct vga_dev *dev, uint16_t scanlines)
{
    vga_write_field(dev, EndVerticalBlanking, scanlines);
}

void
vga_crt_set_maximum_scanline(struct vga_dev *dev, uint8_t value)
{
    vga_write_field(dev, MaximumScanLine, value);
}

void
vga_crt_set_scanline_offset(struct vga_dev *dev, uint16_t offset)
{
    vga_write_field(dev, Offset, offset / 2);
}

void
vga_crt_set_address_size(struct vga_dev *dev, uint8_t size)
{
    int byte_enabled;
    int dword_enabled;
    switch(size)
    {
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
        wprintk("Driver tried to set VGA CRT address size to 0x%x! "
                "(defaulting "
                "to byte addressing)\n",
                size);
        break;
    }

    vga_write_field(dev, DoubleWordAddressing, dword_enabled);
    vga_write_field(dev, WordByteModeSelect, byte_enabled);
}

void
vga_dac_set_color(struct vga_dev *dev,
                  uint8_t index,
                  uint8_t r,
                  uint8_t g,
                  uint8_t b)
{
    spin_lock(&dev->dac_lock);

    vga_write_register(dev, DACAddressWriteMode, index);

    // Officially this should always be RGB
    switch(dev->dac_order)
    {
    case VGA_DAC_ORDER_RGB:
        vga_write_register(dev, DACData, r);
        vga_write_register(dev, DACData, g);
        vga_write_register(dev, DACData, b);
        break;
    case VGA_DAC_ORDER_RBG:
        vga_write_register(dev, DACData, r);
        vga_write_register(dev, DACData, b);
        vga_write_register(dev, DACData, g);
        break;
    case VGA_DAC_ORDER_BGR:
        vga_write_register(dev, DACData, b);
        vga_write_register(dev, DACData, g);
        vga_write_register(dev, DACData, r);
        break;
    case VGA_DAC_ORDER_BRG:
        vga_write_register(dev, DACData, b);
        vga_write_register(dev, DACData, r);
        vga_write_register(dev, DACData, g);
        break;
    case VGA_DAC_ORDER_GRB:
        vga_write_register(dev, DACData, g);
        vga_write_register(dev, DACData, r);
        vga_write_register(dev, DACData, b);
        break;
    case VGA_DAC_ORDER_GBR:
        vga_write_register(dev, DACData, g);
        vga_write_register(dev, DACData, b);
        vga_write_register(dev, DACData, r);
        break;
    default:
        break;
    }

    spin_unlock(&dev->dac_lock);
}

void
vga_crt_disable_retrace(struct vga_dev *dev)
{
    vga_write_field(dev, SyncEnable, 0);
}

void
vga_crt_enable_scan_doubling(struct vga_dev *dev)
{
    vga_write_field(dev, ScanDoubling, 1);
}

void
vga_crt_disable_scan_doubling(struct vga_dev *dev)
{
    vga_write_field(dev, ScanDoubling, 0);
}
