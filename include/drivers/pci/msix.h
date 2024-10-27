#ifndef __KANAWHA__PCI_MSIX_H__
#define __KANAWHA__PCI_MSIX_H__

#include <drivers/pci/cap.h>

struct pci_msix_info {
    struct pci_cap *cap;

    struct pci_bar *bir;
    uint32_t bir_offset;

    struct pci_bar *pending_bir;
    uint32_t pending_bir_offset;
};

int
pci_func_init_msix_info(
        struct pci_func *func);

int
pci_func_deinit_msix_info(
        struct pci_func *func);

int
pci_func_start_msix(
        struct pci_func *func);
int
pci_func_stop_msix(
        struct pci_func *func);

// maximum number of supported IRQ(s) (zero if MSI or MSI-X is not supported)
size_t
pci_func_msix_max_num_irqs(
        struct pci_func *func);

// current number of used IRQ(s) (zero if MSI or MSI-X is not supported)
size_t
pci_func_msix_num_irqs(
        struct pci_func *func);

#endif
