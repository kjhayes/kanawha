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

#define PCI_CFG_BAR_BASE 0x10


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
OP(readb, PCI_CAM_READ8_SIG, ##__VA_ARGS__)\
OP(readw, PCI_CAM_READ16_SIG, ##__VA_ARGS__)\
OP(readl, PCI_CAM_READ32_SIG, ##__VA_ARGS__)\
OP(writeb, PCI_CAM_WRITE8_SIG, ##__VA_ARGS__)\
OP(writew, PCI_CAM_WRITE16_SIG, ##__VA_ARGS__)\
OP(writel, PCI_CAM_WRITE32_SIG, ##__VA_ARGS__)

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
pci_bus_readb(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out)
{
    return pci_domain_readb(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_readw(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out)
{
    return pci_domain_readw(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_readl(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out)
{
    return pci_domain_readl(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            out);
}

static inline int
pci_bus_writeb(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in)
{
    return pci_domain_writeb(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

static inline int
pci_bus_writew(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in)
{
    return pci_domain_writew(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

static inline int
pci_bus_writel(
        struct pci_bus *bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in)
{
    return pci_domain_writel(
            bus->domain,
            bus->bus_index,
            device,
            func,
            offset,
            in);
}

// PCI Device Config Access

static inline int
pci_func_readb(
        struct pci_func *func,
        uint16_t offset,
        uint8_t *out)
{
    return pci_domain_readb(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            out);
}

static inline int
pci_func_readw(
        struct pci_func *func,
        uint16_t offset,
        uint16_t *out)
{
    return pci_domain_readw(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            out);
}

static inline int
pci_func_readl(
        struct pci_func *func,
        uint16_t offset,
        uint32_t *out)
{
    return pci_domain_readl(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            out);
}

static inline int
pci_func_writeb(
        struct pci_func *func,
        uint16_t offset,
        uint8_t in)
{
    return pci_domain_writeb(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            in);
}

static inline int
pci_func_writew(
        struct pci_func *func,
        uint16_t offset,
        uint16_t in)
{
    return pci_domain_writew(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            in);
}

static inline int
pci_func_writel(
        struct pci_func *func,
        uint16_t offset,
        uint32_t in)
{
    return pci_domain_writel(
            func->domain,
            func->device->bus->bus_index,
            func->device->index,
            func->index,
            offset,
            in);
}

static inline uint32_t
pci_func_raw_read_bar(
        struct pci_func *func,
        int bar_index)
{
    int res;
    uint32_t out = 0;
    res = pci_func_readl(
            func,
            PCI_CFG_BAR_BASE+(bar_index*4),
            &out);
    if(res) {
        eprintk("Failed to read PCI BAR!\n");
        return 0;
    }
    return out;
}

static inline void
pci_func_raw_write_bar(
        struct pci_func *func,
        int bar_index,
        uint32_t value)
{
    int res;
    res = pci_func_writel(
            func,
            PCI_CFG_BAR_BASE+(bar_index*4),
            value);
    if(res) {
        eprintk("Failed to write PCI BAR!\n");
    }
}

#endif
