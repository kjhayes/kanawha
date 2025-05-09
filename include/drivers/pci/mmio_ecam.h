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

#endif
