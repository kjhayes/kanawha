
#include <drivers/pci/msi.h>
#include <drivers/pci/msix.h>

int
pci_func_init_irqs(
        struct pci_func *func)
{
    int res;

    func->irq_mode = PCI_IRQ_MODE_NONE;
    func->irq_dev = NULL;
    func->irq_domain = NULL;

    // TODO INT-X

    res = pci_func_init_msi_info(func);
    if(res) {
        return res;
    }
    res = pci_func_init_msix_info(func);
    if(res) {
        pci_func_deinit_msi_info(func);
        return res;
    }
    return 0;
}

int
pci_func_deinit_irqs(
        struct pci_func *func)
{
    int res;

    switch(func->irq_mode) {
      case PCI_IRQ_MODE_INTX:
          return -EUNIMPL;
      case PCI_IRQ_MODE_MSI:
          pci_func_deinit_msi_info(func);
          break;
      case PCI_IRQ_MODE_MSIX:
          pci_func_deinit_msix_info(func);
          break;
      case PCI_IRQ_MODE_NONE:
          break;
      default:
          return -EINVAL;
    }

    return 0;
}

int
pci_func_start_irqs(struct pci_func *func)
{
    if(func->irq_mode != PCI_IRQ_MODE_NONE) {
        return -EALREADY;
    }

    int res;
    if(func->msix_info) {
        res = pci_func_start_msix(func);
        if(res == 0) {
            return 0;
        }
    }

    if(func->msi_info) {
        res = pci_func_start_msi(func);
        if(res == 0) {
            return 0;
        }
    }

    // TODO INT-X

    return -EINVAL;
}

int
pci_func_stop_irqs(struct pci_func *func)
{
    return -EUNIMPL;
}

irq_t
pci_func_get_irq(
        struct pci_func *func,
        hwirq_t hwirq)
{
    if(func->irq_domain != NULL) {
        return irq_domain_revmap(func->irq_domain, hwirq);
    }
    return NULL_IRQ;
}

