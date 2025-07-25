#ifndef __KANAWHA__DRIVERS_VGA_H__
#define __KANAWHA__DRIVERS_VGA_H__

#include <kanawha/spinlock.h>
#include <kanawha/pio.h>
#include <kanawha/mmio.h>

struct vga_dev;

#define vga_read_register(vga_dev_ptr, __REG)\
    vga_read_ ## __REG ## _register(vga_dev_ptr)
#define vga_write_register(vga_dev_ptr, __REG, value)\
    vga_write_ ## __REG ## _register(vga_dev_ptr, value)

#define vga_read_field(vga_dev_ptr, __FIELD)\
    vga_read_ ## __FIELD ## _field(vga_dev_ptr)
#define vga_write_field(vga_dev_ptr, __FIELD, value)\
    vga_write_ ## __FIELD ## _field(vga_dev_ptr, value)

uint8_t
vga_read_graphics_register_set(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_graphics_register_set(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);

uint8_t
vga_read_sequencer_register_set(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_sequencer_register_set(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);

uint8_t
vga_read_crt_register_set(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_crt_register_set(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);

uint8_t
vga_read_attribute_register_set(
        struct vga_dev *dev,
        uint8_t index);
void
vga_write_attribute_register_set(
        struct vga_dev *dev,
        uint8_t index,
        uint8_t value);

#define VGA_PORT_REGISTER_XLIST(X)\
X(AttributeAddressData,       0x3C0, RW)\
X(AttributeAddress,           0x3C0, R)\
X(AttributeDataRead,          0x3C1, RW)\
X(InputStatus0,               0x3C2, R)\
X(MiscellaneousOutputWrite,   0x3C2, W)\
X(SequencerAddress,           0x3C4, RW)\
X(SequencerData,              0x3C5, RW)\
X(DACMask,                    0x3C6, RW)\
X(DACState,                   0x3C7, R)\
X(DACAddressReadMode,         0x3C7, W)\
X(DACAddressWriteMode,        0x3C8, RW)\
X(DACData,                    0x3C9, RW)\
X(FeatureControlRead,         0x3CA, R)\
X(MiscellaneousOutputRead,    0x3CC, R)\
X(GraphicsControllerAddress,  0x3CE, RW)\
X(GraphicsControllerData,     0x3CF, RW)\

#define VGA_PORT_ALT_MONO_REGISTER_XLIST(X)\
X(CRTCControllerAddress, 0x3B4, 0x3D4, RW)\
X(CRTCControllerData,    0x3B5, 0x3D5, RW)\
X(InputStatus1,          0x3BA, 0x3DA, R)\
X(FeatureControlWrite,   0x3BA, 0x3DA, W)\

#define VGA_SPLIT_REGISTER_XLIST(X)\
X(FeatureControl, FeatureControlRead, FeatureControlWrite)\
X(MiscellaneousOutput, MiscellaneousOutputRead, MiscellaneousOutputWrite)\

#define VGA_INDEXED_REGISTER_XLIST(X)\
X(SetReset,                 graphics,   0x00, RW)\
X(EnableSetReset,           graphics,   0x01, RW)\
X(ColorCompare,             graphics,   0x02, RW)\
X(DataRotate,               graphics,   0x03, RW)\
X(ReadMapSelect,            graphics,   0x04, RW)\
X(GraphicsMode,             graphics,   0x05, RW)\
X(MiscellaneousGraphics,    graphics,   0x06, RW)\
X(ColorDontCare,            graphics,   0x07, RW)\
X(BitMask,                  graphics,   0x08, RW)\
X(Reset,                    sequencer,  0x00, RW)\
X(ClockingMode,             sequencer,  0x01, RW)\
X(MapMask,                  sequencer,  0x02, RW)\
X(CharacterMapSelect,       sequencer,  0x03, RW)\
X(SequencerMemoryMode,      sequencer,  0x04, RW)\
X(Palette0,                 attribute,  0x00, RW)\
X(Palette1,                 attribute,  0x01, RW)\
X(Palette2,                 attribute,  0x02, RW)\
X(Palette3,                 attribute,  0x03, RW)\
X(Palette4,                 attribute,  0x04, RW)\
X(Palette5,                 attribute,  0x05, RW)\
X(Palette6,                 attribute,  0x06, RW)\
X(Palette7,                 attribute,  0x07, RW)\
X(Palette8,                 attribute,  0x08, RW)\
X(Palette9,                 attribute,  0x09, RW)\
X(Palette10,                attribute,  0x0A, RW)\
X(Palette11,                attribute,  0x0B, RW)\
X(Palette12,                attribute,  0x0C, RW)\
X(Palette13,                attribute,  0x0D, RW)\
X(Palette14,                attribute,  0x0E, RW)\
X(Palette15,                attribute,  0x0F, RW)\
X(AttributeModeControl,     attribute,  0x10, RW)\
X(OverscanColor,            attribute,  0x11, RW)\
X(ColorPlaneEnable,         attribute,  0x12, RW)\
X(HorizontalPixelPanning,   attribute,  0x13, RW)\
X(ColorSelect,              attribute,  0x14, RW)\
X(HorizontalTotal,          crt,        0x00, RW)\
X(EndHorizontalDisplay,     crt,        0x01, RW)\
X(StartHorizontalBlanking,  crt,        0x02, RW)\
X(EndHorizontalBlanking,    crt,        0x03, RW)\
X(StartHorizontalRetrace,   crt,        0x04, RW)\
X(EndHorizontalRetrace,     crt,        0x05, RW)\
X(VerticalTotal,            crt,        0x06, RW)\
X(Overflow,                 crt,        0x07, RW)\
X(PresetRowScan,            crt,        0x08, RW)\
X(MaximumScanLine,          crt,        0x09, RW)\
X(CursorStart,              crt,        0x0A, RW)\
X(CursorEnd,                crt,        0x0B, RW)\
X(StartAddressHigh,         crt,        0x0C, RW)\
X(StartAddressLow,          crt,        0x0D, RW)\
X(CursorLocationHigh,       crt,        0x0E, RW)\
X(CursorLocationLow,        crt,        0x0F, RW)\
X(VerticalRetraceStart,     crt,        0x10, RW)\
X(VerticalRetraceEnd,       crt,        0x11, RW)\
X(VerticalDisplayEnd,       crt,        0x12, RW)\
X(Offset,                   crt,        0x13, RW)\
X(UnderlineLocation,        crt,        0x14, RW)\
X(StartVerticalBlanking,    crt,        0x15, RW)\
X(EndVerticalBlanking,      crt,        0x16, RW)\
X(CRTCModeControl,          crt,        0x17, RW)\
X(LineCompare,              crt,        0x18, RW)

#define VGA_FIELD_XLIST(X)\
X(SetReset,                                SetReset,                 3,  0)\
X(EnableSetReset,                          EnableSetReset,           3,  0)\
X(ColorCompare,                            ColorCompare,             3,  0)\
X(RotateCount,                             DataRotate,               2,  0)\
X(LogicalOperation,                        DataRotate,               4,  3)\
X(ReadMapSelect,                           ReadMapSelect,            1,  0)\
X(WriteMode,                               GraphicsMode,             1,  0)\
X(ReadMode,                                GraphicsMode,             3,  3)\
X(HostOddEvenMemoryReadAddressingEnable,   GraphicsMode,             4,  4)\
X(ShiftRegisterInterleaveMode,             GraphicsMode,             5,  5)\
X(ColorShiftMode_256,                      GraphicsMode,             6,  6)\
X(AlphanumericModeDisable,                 MiscellaneousGraphics,    0,  0)\
X(ChainOddEvenEnable,                      MiscellaneousGraphics,    1,  1)\
X(MemoryMapSelect,                         MiscellaneousGraphics,    3,  2)\
X(ColorDontCare,                           ColorDontCare,            3,  0)\
X(BitMask,                                 BitMask,                  7,  0)\
X(AsynchronousReset,                       Reset,                    0,  0)\
X(SynchronousReset,                        Reset,                    1,  1)\
X(DotMode_9_8,                             ClockingMode,             0,  0)\
X(ShiftLoadRate,                           ClockingMode,             2,  2)\
X(DotClockRate,                            ClockingMode,             3,  3)\
X(ShiftFourEnable,                         ClockingMode,             4,  4)\
X(ScreenDisable,                           ClockingMode,             5,  5)\
X(MemoryPlaneWriteEnable,                  MapMask,                  3,  0)\
X(ExtendedMemory,                          SequencerMemoryMode,      1,  1)\
X(HostOddEvenMemoryWriteAddressingDisable, SequencerMemoryMode,      2,  2)\
X(Chain4Enable,                            SequencerMemoryMode,      3,  3)\
X(AttributeAddress,                        AttributeAddress,         4,  0)\
X(PaletteAddressSource,                    AttributeAddress,         5,  5)\
X(InternalPaletteIndex0,                   Palette0,                 5,  0)\
X(InternalPaletteIndex1,                   Palette1,                 5,  0)\
X(InternalPaletteIndex2,                   Palette2,                 5,  0)\
X(InternalPaletteIndex3,                   Palette3,                 5,  0)\
X(InternalPaletteIndex4,                   Palette4,                 5,  0)\
X(InternalPaletteIndex5,                   Palette5,                 5,  0)\
X(InternalPaletteIndex6,                   Palette6,                 5,  0)\
X(InternalPaletteIndex7,                   Palette7,                 5,  0)\
X(InternalPaletteIndex8,                   Palette8,                 5,  0)\
X(InternalPaletteIndex9,                   Palette9,                 5,  0)\
X(InternalPaletteIndex10,                  Palette10,                5,  0)\
X(InternalPaletteIndex11,                  Palette11,                5,  0)\
X(InternalPaletteIndex12,                  Palette12,                5,  0)\
X(InternalPaletteIndex13,                  Palette13,                5,  0)\
X(InternalPaletteIndex14,                  Palette14,                5,  0)\
X(InternalPaletteIndex15,                  Palette15,                5,  0)\
X(AttributeControllerGraphicsEnable,       AttributeModeControl,     0,  0)\
X(MonochromeEmulation,                     AttributeModeControl,     1,  1)\
X(LineGraphicsEnable,                      AttributeModeControl,     2,  2)\
X(BlinkEnable,                             AttributeModeControl,     3,  3)\
X(PixelPanningMode,                        AttributeModeControl,     5,  5)\
X(ColorEnable_8Bit,                        AttributeModeControl,     6,  6)\
X(PaletteBits_5_4_Select,                  AttributeModeControl,     7,  7)\
X(OverscanPaletteIndex,                    OverscanColor,            7,  0)\
X(ColorPlaneEnable,                        ColorPlaneEnable,         3,  0)\
X(PixelShiftCount,                         HorizontalPixelPanning,   3,  0)\
X(ColorSelect_5_4,                         ColorSelect,              1,  0)\
X(ColorSelect_7_6,                         ColorSelect,              3,  2)\
X(HorizontalTotal,                         HorizontalTotal,          7,  0)\
X(EndHorizontalDisplay,                    EndHorizontalDisplay,     7,  0)\
X(StartHorizontalBlanking,                 StartHorizontalBlanking,  7,  0)\
X(DisplayEnableSkew,                       EndHorizontalBlanking,    6,  5)\
X(EnableVerticalRetraceAccess,             EndHorizontalBlanking,    7,  7)\
X(StartHorizontalRetrace,                  StartHorizontalRetrace,   7,  0)\
X(EndHorizontalRetrace,                    EndHorizontalRetrace,     4,  0)\
X(HorizontalRetraceSkew,                   EndHorizontalRetrace,     6,  5)\
X(PresetRowScan,                           PresetRowScan,            4,  0)\
X(BytePanning,                             PresetRowScan,            6,  5)\
X(MaximumScanLine,                         MaximumScanLine,          4,  0)\
X(ScanDoubling,                            MaximumScanLine,          7,  7)\
X(CursorScanLineStart,                     CursorStart,              4,  0)\
X(CursorDisable,                           CursorStart,              5,  5)\
X(CursorScanLineEnd,                       CursorEnd,                4,  0)\
X(CursorSkew,                              CursorEnd,                6,  5)\
X(VerticalRetraceEnd,                      VerticalRetraceEnd,       3,  0)\
X(MemoryRefreshBandwidth,                  VerticalRetraceEnd,       6,  6)\
X(CRTCRegistersProtectEnable,              VerticalRetraceEnd,       7,  7)\
X(Offset,                                  Offset,                   7,  0)\
X(UnderlineLocation,                       UnderlineLocation,        4,  0)\
X(DivideMemoryAddressClockby4,             UnderlineLocation,        5,  5)\
X(DoubleWordAddressing,                    UnderlineLocation,        6,  6)\
X(EndVerticalBlanking,                     EndVerticalBlanking,      6,  0)\
X(MapDisplayAddress13,                     CRTCModeControl,          0,  0)\
X(MapDisplayAddress14,                     CRTCModeControl,          1,  1)\
X(DivideScanLineClockby2,                  CRTCModeControl,          2,  2)\
X(DivideMemoryAddressClockby2,             CRTCModeControl,          3,  3)\
X(AddressWrapSelect,                       CRTCModeControl,          5,  5)\
X(WordByteModeSelect,                      CRTCModeControl,          6,  6)\
X(SyncEnable,                              CRTCModeControl,          7,  7)\
X(DACWriteAddress,                         DACAddressWriteMode,      7,  0)\
X(DACReadAddress,                          DACAddressReadMode,       7,  0)\
X(DACData,                                 DACData,                  5,  0)\
X(DACState,                                DACState,                 1,  0)\
X(InputOutputAddressSelect,                MiscellaneousOutput,      0,  0)\
X(RAMEnable,                               MiscellaneousOutput,      1,  1)\
X(ClockSelect,                             MiscellaneousOutput,      3,  2)\
X(OddEvenPageSelect,                       MiscellaneousOutput,      5,  5)\
X(HorizontalSyncPolarity,                  MiscellaneousOutput,      6,  6)\
X(VerticalSyncPolarity,                    MiscellaneousOutput,      7,  7)\
X(FeatureControlBit0,                      FeatureControl,           0,  0)\
X(FeatureControlBit1,                      FeatureControl,           1,  1)\
X(SwitchSense,                             InputStatus0,             4,  4)\
X(DisplayDisabled,                         InputStatus1,             0,  0)\
X(VerticalRetrace,                         InputStatus1,             3,  3)\

#define VGA_DOUBLE_SPLIT_FIELD_XLIST(X)\
X(CursorLocation, CursorLocationHigh, 7, 0, CursorLocationLow, 7, 0)\
X(EndHorizontalBlanking, EndHorizontalRetrace, 7, 7, EndHorizontalBlanking, 4, 0)\
X(LineCompare, MaximumScanLine, 6, 6, LineCompare, 7, 0)\
X(StartAddress, StartAddressHigh, 7, 0, StartAddressLow, 7, 0)\
X(CharacterSetASelect, CharacterMapSelect, 5, 5, CharacterMapSelect, 3, 2)\
X(CharacterSetBSelect, CharacterMapSelect, 4, 4, CharacterMapSelect, 1, 0)\

#define VGA_TRIPLE_SPLIT_FIELD_XLIST(X)\
X(StartVerticalBlanking,  MaximumScanLine,  5,  5,  Overflow,  3,  3,  StartVerticalBlanking,  7,  0)\
X(VerticalTotal,          Overflow,         5,  5,  Overflow,  0,  0,  VerticalTotal,          7,  0)\
X(VerticalDisplayEnd,     Overflow,         6,  6,  Overflow,  1,  1,  VerticalDisplayEnd,     7,  0)\
X(VerticalRetraceStart,   Overflow,         7,  7,  Overflow,  2,  2,  VerticalRetraceStart,   7,  0)\

struct vga_dev
{
    spinlock_t graphics_lock;
    uint8_t graphics_index;

    spinlock_t seq_lock;
    uint8_t seq_index;

    spinlock_t crt_lock;
    uint8_t crt_index;

    spinlock_t attribute_lock;

    spinlock_t dac_lock;

    spinlock_t mode_lock;
};

int
vga_dev_init(
        struct vga_dev *dev);

#define VGA_READ_REGISTER_ATTRIBUTES_R \
    __attribute__((always_inline))

#define VGA_READ_REGISTER_ATTRIBUTES_W \
    __attribute__((error("Cannot read a register which is write-only!")))\
    __attribute__((noinline))

#define VGA_READ_REGISTER_ATTRIBUTES_RW \
    __attribute__((always_inline))

#define VGA_WRITE_REGISTER_ATTRIBUTES_R \
    __attribute__((error("Cannot write a register which is read-only!")))\
    __attribute__((noinline))

#define VGA_WRITE_REGISTER_ATTRIBUTES_W \
    __attribute__((always_inline))

#define VGA_WRITE_REGISTER_ATTRIBUTES_RW \
    __attribute__((always_inline))

#define DEFINE_VGA_READ_ALT_MONO_PORT_REGISTER(__REG, __PORT_MONO, __PORT_COLOR, __ACC)\
static inline uint8_t vga_read_InputOutputAddressSelect_field(struct vga_dev *); \
VGA_READ_REGISTER_ATTRIBUTES_ ## __ACC \
static inline uint8_t \
vga_read_ ## __REG ## _register(struct vga_dev *dev) {\
    int color = vga_read_field(dev, InputOutputAddressSelect);\
    return color ? inb(__PORT_COLOR) : inb(__PORT_MONO);\
}

#define DEFINE_VGA_WRITE_ALT_MONO_PORT_REGISTER(__REG, __PORT_MONO, __PORT_COLOR, __ACC)\
static inline uint8_t vga_read_InputOutputAddressSelect_field(struct vga_dev *); \
VGA_WRITE_REGISTER_ATTRIBUTES_ ## __ACC \
static inline void \
vga_write_ ## __REG ## _register(struct vga_dev *dev, uint8_t value) {\
    int color = vga_read_field(dev, InputOutputAddressSelect);\
    if(color) {\
        outb(__PORT_COLOR, value);\
    } else {\
        outb(__PORT_MONO, value);\
    }\
}

#define DEFINE_VGA_ALT_MONO_PORT_REGISTER_ACCESSORS(__REG, __MONO_PORT, __COLOR_PORT, __ACC)\
    DEFINE_VGA_READ_ALT_MONO_PORT_REGISTER(__REG, __MONO_PORT, __COLOR_PORT, __ACC)\
    DEFINE_VGA_WRITE_ALT_MONO_PORT_REGISTER(__REG, __MONO_PORT, __COLOR_PORT, __ACC)

VGA_PORT_ALT_MONO_REGISTER_XLIST(DEFINE_VGA_ALT_MONO_PORT_REGISTER_ACCESSORS)

#define DEFINE_VGA_READ_SPLIT_REGISTER(__REG, __READ_REG)\
static inline uint8_t vga_read_ ## __READ_REG ## _register(struct vga_dev *); \
static inline uint8_t \
vga_read_ ## __REG ## _register(struct vga_dev *dev) {\
    return vga_read_register(dev, __READ_REG);\
}

#define DEFINE_VGA_WRITE_SPLIT_REGISTER(__REG, __WRITE_REG)\
static inline void vga_write_ ## __WRITE_REG ## _register(struct vga_dev *, uint8_t); \
static inline void \
vga_write_ ## __REG ## _register(struct vga_dev *dev, uint8_t value) {\
    vga_write_register(dev, __WRITE_REG, value);\
}

#define DEFINE_VGA_SPLIT_REGISTER_ACCESSORS(__REG, __READ_REG, __WRITE_REG)\
    DEFINE_VGA_READ_SPLIT_REGISTER(__REG, __READ_REG)\
    DEFINE_VGA_WRITE_SPLIT_REGISTER(__REG, __WRITE_REG)

VGA_SPLIT_REGISTER_XLIST(DEFINE_VGA_SPLIT_REGISTER_ACCESSORS)

#define DEFINE_VGA_READ_PORT_REGISTER(__REG, __PORT, __ACC)\
VGA_READ_REGISTER_ATTRIBUTES_ ## __ACC \
static inline uint8_t \
vga_read_ ## __REG ## _register(struct vga_dev *dev) {\
    return inb(__PORT);\
}

#define DEFINE_VGA_WRITE_PORT_REGISTER(__REG, __PORT, __ACC)\
VGA_WRITE_REGISTER_ATTRIBUTES_ ## __ACC \
static inline void \
vga_write_ ## __REG ## _register(struct vga_dev *dev, uint8_t value) {\
    outb(__PORT, value);\
}

#define DEFINE_VGA_PORT_REGISTER_ACCESSORS(__REG, __PORT, __ACC)\
    DEFINE_VGA_READ_PORT_REGISTER(__REG, __PORT, __ACC)\
    DEFINE_VGA_WRITE_PORT_REGISTER(__REG, __PORT, __ACC)

VGA_PORT_REGISTER_XLIST(DEFINE_VGA_PORT_REGISTER_ACCESSORS)

#define DEFINE_VGA_READ_INDEXED_REGISTER(__REG, __REG_SET, __INDEX, __ACC)\
VGA_READ_REGISTER_ATTRIBUTES_ ## __ACC \
static inline uint8_t \
vga_read_ ## __REG ## _register(struct vga_dev *dev) {\
    return vga_read_ ## __REG_SET ## _register_set(dev, (__INDEX));\
}


#define DEFINE_VGA_WRITE_INDEXED_REGISTER(__REG, __REG_SET, __INDEX, __ACC)\
VGA_WRITE_REGISTER_ATTRIBUTES_ ## __ACC \
static inline void \
vga_write_ ## __REG ## _register(struct vga_dev *dev, uint8_t value) {\
    vga_write_ ## __REG_SET ## _register_set(dev, (__INDEX), value);\
    DEBUG_ASSERT_MSG(vga_read_register(dev, __REG) == value, "Found sticky bit in VGA register " #__REG "\n");\
}

#define DEFINE_VGA_INDEXED_REGISTER_ACCESSORS(__REG, __REG_SET, __INDEX, __ACC)\
    DEFINE_VGA_READ_INDEXED_REGISTER(__REG, __REG_SET, __INDEX, __ACC)\
    DEFINE_VGA_WRITE_INDEXED_REGISTER(__REG, __REG_SET, __INDEX, __ACC)

VGA_INDEXED_REGISTER_XLIST(DEFINE_VGA_INDEXED_REGISTER_ACCESSORS)

#define DEFINE_VGA_READ_FIELD(__FIELD, __REG, __MSB, __LSB)\
static inline uint8_t \
vga_read_ ## __FIELD ## _field(struct vga_dev *dev) {\
    int shift_amt = __LSB;\
    int bitcount = (__MSB - __LSB) + 1;\
    int bitmask = (1ULL<<bitcount)-1;\
    uint8_t reg_value = vga_read_register(dev, __REG);\
    return (reg_value>>shift_amt) & bitmask;\
}

#define DEFINE_VGA_WRITE_FIELD(__FIELD, __REG, __MSB, __LSB)\
static inline void \
vga_write_ ## __FIELD ## _field(struct vga_dev *dev, uint8_t value) {\
    int shift_amt = __LSB;\
    int bitcount = (__MSB - __LSB) + 1;\
    int bitmask = (1ULL<<bitcount)-1;\
    uint8_t reg_value = vga_read_register(dev, __REG);\
    reg_value &= ~(bitmask << shift_amt);\
    reg_value |= ((value & bitmask) << shift_amt);\
    vga_write_register(dev, __REG, reg_value);\
}

#define DEFINE_VGA_FIELD_ACCESSORS(__FIELD, __REG, __MSB, __LSB)\
        DEFINE_VGA_READ_FIELD(__FIELD, __REG, __MSB, __LSB)\
        DEFINE_VGA_WRITE_FIELD(__FIELD, __REG, __MSB, __LSB)

VGA_FIELD_XLIST(DEFINE_VGA_FIELD_ACCESSORS)

#define DEFINE_VGA_READ_DOUBLE_SPLIT_FIELD(__FIELD, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
static inline uint16_t \
vga_read_ ## __FIELD ## _field(struct vga_dev *dev) {\
    uint16_t value;\
    {\
        int shift_amt = __LSB1;\
        int bitcount = (__MSB1 - __LSB1) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG1);\
        value = (reg_value>>shift_amt) & bitmask;\
    }\
    {\
        int shift_amt = __LSB0;\
        int bitcount = (__MSB0 - __LSB0) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG0);\
        value << bitcount;\
        value |= (reg_value>>shift_amt) & bitmask;\
    }\
    return value;\
}

#define DEFINE_VGA_WRITE_DOUBLE_SPLIT_FIELD(__FIELD, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
static inline void \
vga_write_ ## __FIELD ## _field(struct vga_dev *dev, uint16_t value) {\
     {\
        int shift_amt = __LSB0;\
        int bitcount = (__MSB0 - __LSB0) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG0);\
        reg_value &= ~(bitmask << shift_amt);\
        reg_value |= ((value & bitmask) << shift_amt);\
        vga_write_register(dev, __REG0, reg_value);\
        value >> bitcount;\
    }\
    {\
        int shift_amt = __LSB1;\
        int bitcount = (__MSB1 - __LSB1) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG1);\
        reg_value &= ~(bitmask << shift_amt);\
        reg_value |= ((value & bitmask) << shift_amt);\
        vga_write_register(dev, __REG1, reg_value);\
    }\
}

#define DEFINE_VGA_DOUBLE_SPLIT_FIELD_ACCESSORS(__FIELD, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
        DEFINE_VGA_READ_DOUBLE_SPLIT_FIELD(__FIELD, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
        DEFINE_VGA_WRITE_DOUBLE_SPLIT_FIELD(__FIELD, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)

VGA_DOUBLE_SPLIT_FIELD_XLIST(DEFINE_VGA_DOUBLE_SPLIT_FIELD_ACCESSORS)

#define DEFINE_VGA_READ_TRIPLE_SPLIT_FIELD(__FIELD, __REG2, __MSB2, __LSB2, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
static inline uint16_t \
vga_read_ ## __FIELD ## _field(struct vga_dev *dev) {\
    uint16_t value;\
    {\
        int shift_amt = __LSB2;\
        int bitcount = (__MSB2 - __LSB2) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG2);\
        value = (reg_value>>shift_amt) & bitmask;\
    }\
    {\
        int shift_amt = __LSB1;\
        int bitcount = (__MSB1 - __LSB1) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG1);\
        value << bitcount;\
        value |= (reg_value>>shift_amt) & bitmask;\
    }\
    {\
        int shift_amt = __LSB0;\
        int bitcount = (__MSB0 - __LSB0) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG0);\
        value << bitcount;\
        value |= (reg_value>>shift_amt) & bitmask;\
    }\
    return value;\
}
#define DEFINE_VGA_WRITE_TRIPLE_SPLIT_FIELD(__FIELD, __REG2, __MSB2, __LSB2, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
static inline void \
vga_write_ ## __FIELD ## _field(struct vga_dev *dev, uint16_t value) {\
     {\
        int shift_amt = __LSB0;\
        int bitcount = (__MSB0 - __LSB0) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG0);\
        reg_value &= ~(bitmask << shift_amt);\
        reg_value |= ((value & bitmask) << shift_amt);\
        vga_write_register(dev, __REG0, reg_value);\
        value >> bitcount;\
    }\
    {\
        int shift_amt = __LSB1;\
        int bitcount = (__MSB1 - __LSB1) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG1);\
        reg_value &= ~(bitmask << shift_amt);\
        reg_value |= ((value & bitmask) << shift_amt);\
        vga_write_register(dev, __REG1, reg_value);\
        value >> bitcount;\
    }\
    {\
        int shift_amt = __LSB2;\
        int bitcount = (__MSB2 - __LSB2) + 1;\
        int bitmask = (1ULL<<bitcount)-1;\
        uint8_t reg_value = vga_read_register(dev, __REG2);\
        reg_value &= ~(bitmask << shift_amt);\
        reg_value |= ((value & bitmask) << shift_amt);\
        vga_write_register(dev, __REG2, reg_value);\
    }\
}

#define DEFINE_VGA_TRIPLE_SPLIT_FIELD_ACCESSORS(__FIELD, __REG2, __MSB2, __LSB2, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
        DEFINE_VGA_READ_TRIPLE_SPLIT_FIELD(__FIELD, __REG2, __MSB2, __LSB2, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)\
        DEFINE_VGA_WRITE_TRIPLE_SPLIT_FIELD(__FIELD, __REG2, __MSB2, __LSB2, __REG1, __MSB1, __LSB1, __REG0, __MSB0, __LSB0)

VGA_TRIPLE_SPLIT_FIELD_XLIST(DEFINE_VGA_TRIPLE_SPLIT_FIELD_ACCESSORS)


// Specific Accessors

void
vga_lock_crt_reg(
        struct vga_dev *dev);
void
vga_unlock_crt_reg(
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
