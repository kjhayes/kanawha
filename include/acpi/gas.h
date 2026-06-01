#ifndef __KANAWHA__ACPI_GAS_H__
#define __KANAWHA__ACPI_GAS_H__

#include <kanawha/attribute.h>
#include <kanawha/types.h>

#define DECLARE_U8_ENUMS(__NAME, __VAL) \
    __NAME = (uint8_t)__VAL,

#define ACPI_GAS_ASID_XLIST(X)                                                 \
    X(ACPI_GAS_ASID_MMIO, 0x00)                                                \
    X(ACPI_GAS_ASID_PIO, 0x01)                                                 \
    X(APCI_GAS_ASID_PCI_CFG, 0x02)                                             \
    X(ACPI_GAS_ASID_EMBEDDED, 0x03)                                            \
    X(ACPI_GAS_ASID_SMBUS, 0x04)                                               \
    X(ACPI_GAS_ASID_CMOS, 0x05)                                                \
    X(ACPI_GAS_ASID_PCI_BAR, 0x06)                                             \
    X(ACPI_GAS_ASID_IPMI, 0x07)                                                \
    X(ACPI_GAS_ASID_GP_IO, 0x08)                                               \
    X(ACPI_GAS_ASID_GENERIC_SERIAL, 0x09)                                      \
    X(ACPI_GAS_ASID_PCC, 0x0A)                                                 \
    X(ACPI_GAS_ASID_PRM, 0x0B)
enum {
ACPI_GAS_ASID_XLIST(DECLARE_U8_ENUMS)
};

#define ACPI_GAS_ACCESS_SIZE_XLIST(X)                                          \
    X(ACPI_GAS_ACCESS_SIZE_BYTE, 0x1)                                          \
    X(ACPI_GAS_ACCESS_SIZE_WORD, 0x2)                                          \
    X(ACPI_GAS_ACCESS_SIZE_DWORD, 0x3)                                         \
    X(ACPI_GAS_ACCESS_SIZE_QUAD, 0x4)
enum {
ACPI_GAS_ACCESS_SIZE_XLIST(DECLARE_U8_ENUMS)
};

struct __packed acpi_gas
{
    uint8_t asid;
    uint8_t reg_bit_width;
    uint8_t reg_bit_offset;
    uint8_t access_size;
    uint64_t address;
};

#undef DECLARE_U8_ENUMS

#endif
