#ifndef __KANAWHA__MMIO_ECAM_PCI_H__
#define __KANAWHA__MMIO_ECAM_PCI_H__

#include <kanawha/pointer.h>
#include <kanawha/types.h>
#include <drivers/pci/pci.h>

struct mmio_ecam_pci_domain
{
    void __phys *base_addr;
    size_t size;

    struct pci_domain domain;
};

int
register_mmio_ecam_pci_domain(
        struct mmio_ecam_pci_domain *domain,
        void __phys *base_addr,
        size_t size);

#endif
