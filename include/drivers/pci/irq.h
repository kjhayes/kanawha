#ifndef __KANAWHA__PCI_IRQ_H__
#define __KANAWHA__PCI_IRQ_H__

#include <drivers/pci/msi.h>
#include <drivers/pci/msix.h>

static inline size_t
pci_func_max_num_irqs(
        struct pci_func *func)
{
    if(func->msix_info) {
        return pci_func_msix_max_num_irqs(func);
    }
    if(func->msi_info) {
        return pci_func_msi_max_num_irqs(func);
    }

    // TODO INT-X

    return 0;
}

static inline size_t
pci_func_num_irqs(
        struct pci_func *func)
{
    if(func->msix_info) {
        return pci_func_msix_num_irqs(func);
    }
    if(func->msi_info) {
        return pci_func_msi_num_irqs(func);
    }

    // TODO INT-X

    return 0;
}

int pci_func_init_irqs(struct pci_func *func);

#endif
