#ifndef __KANAWHA__MMIO_ECAM_PCI_H__
#define __KANAWHA__MMIO_ECAM_PCI_H__

#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/pointer.h>
#include <kanawha/types.h>

struct mmio_pci_ecam
{
    struct pci_cam cam;
    uint16_t segment_id;
    void __phys *base_addr;
    size_t size;
    void __mmio *mmio_base;
};

int
register_mmio_pci_ecam(struct mmio_pci_ecam *ecam,
                       uint16_t segment_id,
                       void __phys *base_addr,
                       size_t size);

static inline size_t
pci_mmio_ecam_size_for_n_buses(size_t num_buses)
{
    // Each function has 0x1000 bytes of space in ECAM
    return 0x1000ULL * num_buses * PCI_MAX_DEVICES_PER_BUS *
           PCI_MAX_FUNC_PER_DEVICE;
}

#endif
