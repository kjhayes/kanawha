#ifndef __KANAWHA__PCI_CAP_H__
#define __KANAWHA__PCI_CAP_H__

#include <kanawha/list.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>

#define PCI_CAP_ID_MSI             0x5
#define PCI_CAP_ID_MSIX            0x11
#define PCI_CAP_ID_VENDOR_SPECIFIC 0x9

struct pci_cap
{
    ilist_node_t list_node;

    uint16_t cfg_offset;
    uint8_t cap_id;
};

int
pci_func_init_caps(
        struct pci_func *func);

int
pci_func_deinit_caps(
        struct pci_func *func);

struct pci_cap *
pci_func_find_cap(
        struct pci_func *func,
        uint8_t cap_id);

struct pci_cap *
pci_func_find_next_cap(
        struct pci_func *func,
        struct pci_cap *cap,
        uint8_t cap_id);

// Capability Read/Write Config Space Utils

static inline uint8_t
pci_cap_readb(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset)
{
    uint8_t val;
    int res = pci_func_readb(func, cap->cfg_offset + offset, &val);
    if(res) {
        return 0;
    }
    return val;
}

static inline uint16_t
pci_cap_readw(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset)
{
    uint16_t val;
    int res = pci_func_readw(func, cap->cfg_offset + offset, &val);
    if(res) {
        return 0;
    }
    return val;
}

static inline uint32_t
pci_cap_readl(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset)
{
    uint32_t val;
    int res = pci_func_readl(func, cap->cfg_offset + offset, &val);
    if(res) {
        return 0;
    }
    return val;
}

static inline int
pci_cap_writeb(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset,
        uint8_t val)
{
    int res = pci_func_writeb(func, cap->cfg_offset + offset, val);
    if(res) {
        return res;
    }
    return 0;
}

static inline int 
pci_cap_writew(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset,
        uint16_t val)
{
    int res = pci_func_writew(func, cap->cfg_offset + offset, val);
    if(res) {
        return res;
    }
    return 0;
}

static inline int 
pci_cap_writel(
        struct pci_func *func,
        struct pci_cap *cap,
        uint16_t offset,
        uint32_t val)
{
    int res = pci_func_writel(func, cap->cfg_offset + offset, val);
    if(res) {
        return res;
    }
    return 0;
}

#endif
