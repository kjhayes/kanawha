
#include <drivers/pci/msi.h>
#include <drivers/pci/msix.h>
#include <kanawha/irq_domain.h>

int
pci_func_init_irqs(struct pci_func *func)
{
    int res;

    func->irq_mode = PCI_IRQ_MODE_NONE;
    func->irq_dev = NULL;
    func->irq_domain = NULL;

    // TODO INT-X

    res = pci_func_init_msi_info(func);
    if(res)
    {
        return res;
    }
    res = pci_func_init_msix_info(func);
    if(res)
    {
        pci_func_deinit_msi_info(func);
        return res;
    }
    return 0;
}

int
pci_func_deinit_irqs(struct pci_func *func)
{
    int res;

    switch(func->irq_mode)
    {
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
pci_func_start_irqs(struct pci_func *func, size_t req_num)
{
    if(func->irq_mode != PCI_IRQ_MODE_NONE)
    {
        return -EALREADY;
    }

    int res;
    res = pci_func_start_msix(func, req_num);
    if(res == 0)
    {
        return 0;
    }
    else
    {
        wprintk("pci_func_start_irqs: MSI-X Failed (err=%s)\n", errnostr(res));
    }

    res = pci_func_start_msi(func, req_num);
    if(res == 0)
    {
        return 0;
    }
    else
    {
        wprintk("pci_func_start_irqs: MSI Failed (err=%s)\n", errnostr(res));
    }

    // TODO INT-X

    printk("pci_func_start_irqs: No suitable IRQ method could be started!\n");
    return -EINVAL;
}

size_t
pci_func_num_irqs(struct pci_func *func)
{
    if(func->irq_mode == PCI_IRQ_MODE_NONE)
    {
        return 0;
    }
    if(func->irq_domain == 0)
    {
        return 0;
    }
    return irq_domain_num_irqs(func->irq_domain);
}

int
pci_func_stop_irqs(struct pci_func *func)
{
    return -EUNIMPL;
}

irq_t
pci_func_get_irq(struct pci_func *func, hwirq_t hwirq)
{
    if(func->irq_domain != NULL)
    {
        irq_t irq = irq_domain_revmap(func->irq_domain, hwirq);
        if(irq == NULL_IRQ)
        {
            eprintk("pci_func_get_irq: irq_domain_revmap returned "
                    "IRQ_NULL!\n");
            irq_domain_dump(do_printk, func->irq_domain);
        }
        return irq;
    }
    eprintk("pci_func_get_irq: Function has NULL irq_domain!\n");
    return NULL_IRQ;
}
