#ifndef __KANAWHA__PCI_CFG_H__
#define __KANAWHA__PCI_CFG_H__

#include <drivers/pci/pci.h>
#include <kanawha/ops.h>

#define PCI_HEADER_TYPE_DEVICE             0x0
#define PCI_HEADER_TYPE_PCI_PCI_BRIDGE     0x1
#define PCI_HEADER_TYPE_PCI_CARDBUS_BRIDGE 0x2

#define PCI_CFG_VENDOR_ID   0x0
#define PCI_CFG_DEVICE_ID   0x2
#define PCI_CFG_COMMAND     0x4
#define PCI_CFG_STATUS      0x6
#define PCI_CFG_REV_ID      0x8
#define PCI_CFG_PROG_IF     0x9
#define PCI_CFG_SUBCLASS    0xA
#define PCI_CFG_CLASS       0xB
#define PCI_CFG_CACHE_LINE  0xC
#define PCI_CFG_LAT_TIMER   0xD
#define PCI_CFG_HEADER_TYPE 0xE
#define PCI_CFG_BIST        0xF

#define PCI_CFG_PCI_BRIDGE_PRIMARY_BUS   0x18
#define PCI_CFG_PCI_BRIDGE_SECONDARY_BUS 0x19


/*
 * "CAM" here refers to any configuration access
 * mechanism (including but not necessarily PCIe ECAM)
 * hence why "offset" is 16-bit instead of 8-bit
 */

#define PCI_CAM_READ8_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint8_t*, out)

#define PCI_CAM_READ16_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint16_t*, out)

#define PCI_CAM_READ32_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint32_t*, out)

#define PCI_CAM_WRITE8_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint8_t, in)

#define PCI_CAM_WRITE16_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint16_t, in)

#define PCI_CAM_WRITE32_SIG(RET,ARG)\
RET(int)\
ARG(uint8_t, bus)\
ARG(uint8_t, device)\
ARG(uint8_t, func)\
ARG(uint16_t, offset)\
ARG(uint32_t, in)

#define PCI_CAM_OP_LIST(OP, ...)\
OP(read8, PCI_CAM_READ8_SIG, ##__VA_ARGS__)\
OP(read16, PCI_CAM_READ16_SIG, ##__VA_ARGS__)\
OP(read32, PCI_CAM_READ32_SIG, ##__VA_ARGS__)\
OP(write8, PCI_CAM_WRITE8_SIG, ##__VA_ARGS__)\
OP(write16, PCI_CAM_WRITE16_SIG, ##__VA_ARGS__)\
OP(write32, PCI_CAM_WRITE32_SIG, ##__VA_ARGS__)

struct pci_domain;

struct pci_cam {
DECLARE_OP_LIST_PTRS(PCI_CAM_OP_LIST, struct pci_domain *)
};

DEFINE_OP_LIST_WRAPPERS(
        PCI_CAM_OP_LIST,
        static inline,
        /* No Prefix */,
        pci_domain,
        ->cam->,
        SELF_ACCESSOR)

#undef PCI_CAM_OP_LIST
#undef PCI_CAM_READ8_SIG
#undef PCI_CAM_READ16_SIG
#undef PCI_CAM_READ32_SIG
#undef PCI_CAM_WRITE8_SIG
#undef PCI_CAM_WRITE16_SIG
#undef PCI_CAM_WRITE32_SIG

// PCI Bus Config Access

static inline int
pci_bus_read8(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out)
{
    return pci_domain_read8(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_read16(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out)
{
    return pci_domain_read16(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_read32(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out)
{
    return pci_domain_read32(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_write8(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in)
{
    return pci_domain_write8(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

static inline int
pci_bus_write16(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in)
{
    return pci_domain_write16(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

static inline int
pci_bus_write32(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in)
{
    return pci_domain_write32(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

// PCI Device Config Access

static inline int
pci_device_read8(
        struct pci_device *dev,
        uint16_t offset,
        uint8_t *out)
{
    return pci_domain_read8(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            out);
}

static inline int
pci_device_read16(
        struct pci_device *dev,
        uint16_t offset,
        uint16_t *out)
{
    return pci_domain_read16(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            out);
}

static inline int
pci_device_read32(
        struct pci_device *dev,
        uint16_t offset,
        uint32_t *out)
{
    return pci_domain_read32(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            out);
}

static inline int
pci_device_write8(
        struct pci_device *dev,
        uint16_t offset,
        uint8_t in)
{
    return pci_domain_write8(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            in);
}

static inline int
pci_device_write16(
        struct pci_device *dev,
        uint16_t offset,
        uint16_t in)
{
    return pci_domain_write16(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            in);
}

static inline int
pci_device_write32(
        struct pci_device *dev,
        uint16_t offset,
        uint32_t in)
{
    return pci_domain_write32(
            dev->domain,
            dev->bus->bus_index,
            dev->dev_index,
            dev->func_index,
            offset,
            in);
}


#endif
