#ifndef __KANAWHA__MMIO_ECAM_PCI_H__
#define __KANAWHA__MMIO_ECAM_PCI_H__

#include <kanawha/pointer.h>
#include <kanawha/types.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>

struct mmio_pci_ecam
{
    struct pci_cam cam;
    uint16_t segment_id;
    void __phys *base_addr;
    size_t size;
};

int
register_mmio_pci_ecam(
        struct mmio_pci_ecam *ecam,
        uint16_t segment_id,
        void __phys *base_addr,
        size_t size);

static inline size_t
pci_mmio_ecam_size_for_n_buses(
        size_t num_buses)
{
    // Each function has 0x1000 bytes of space in ECAM
    return 0x1000ULL * num_buses * PCI_MAX_DEVICES_PER_BUS * PCI_MAX_FUNC_PER_DEVICE;
}

#endif
