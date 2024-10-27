#ifndef __KANAWHA__PCI_MSI_H__
#define __KANAWHA__PCI_MSI_H__

#include <drivers/pci/cap.h>

struct pci_msi_info {
    struct pci_cap *cap;
};

int
pci_func_init_msi_info(
        struct pci_func *func);

int
pci_func_deinit_msi_info(
        struct pci_func *func);

int
pci_func_start_msi(
        struct pci_func *func);
int
pci_func_stop_msi(
        struct pci_func *func);

// maximum number of supported IRQ(s) (zero if MSI or MSI-X is not supported)
size_t
pci_func_msi_max_num_irqs(
        struct pci_func *func);

// current number of used IRQ(s) (zero if MSI or MSI-X is not supported)
size_t
pci_func_msi_num_irqs(
        struct pci_func *func);

#endif
