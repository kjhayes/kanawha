#ifndef __KANAWHA__PCI_IRQ_H__
#define __KANAWHA__PCI_IRQ_H__

#include <drivers/pci/msi.h>
#include <drivers/pci/msix.h>

int pci_func_init_irqs(struct pci_func *func);
int pci_func_deinit_irqs(struct pci_func *func);

// Makes sure that func->irq_domain is populated,
// but does not specify which method (INT-X, MSI, or MSI-X) is actually used.
int pci_func_start_irqs(struct pci_func *func);

// Free's the IRQ domain associated with this func
// if one exists
int pci_func_stop_irqs(struct pci_func *func);

// Can only be called after pci_func_start_irqs (or equivalent INT-X, MSI, or MSI-X function)
irq_t pci_func_get_irq(struct pci_func *func, hwirq_t hwirq);

#endif
