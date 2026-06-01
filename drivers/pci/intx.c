
#include <drivers/pci/intx.h>
#include <drivers/pci/cfg.h>
#include <kanawha/printk.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>

static inline int
pci_intx_ack_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    return 0;
}
static inline int
pci_intx_eoi_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    return 0;
}
static inline int
pci_intx_mask_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    return 0;
}
static inline int
pci_intx_unmask_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    return 0;
}
static inline unsigned long
pci_intx_irq_status(struct irq_dev *dev, hwirq_t hwirq)
{
    return IRQ_STATUS_UNKNOWN;
}
static inline int
pci_intx_trigger_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    return 0;
}
static inline int
pci_intx_describe_irq(
        struct irq_dev *dev,
        hwirq_t hwirq,
        char *buffer,
        size_t buflen)
{
    struct pci_intx_info *info = container_of(dev, struct pci_intx_info, irq_dev);
    if(hwirq >= 1 && hwirq <= 4) {
        snprintk(
                buffer,
                buflen,
                "%s-int-%c",
                info->func->namebuf,
                hwirq == 1 ? 'A' :
                hwirq == 2 ? 'B' :
                hwirq == 3 ? 'C' :
                hwirq == 4 ? 'D' :
                '?');
    } else {
        snprintk(
                buffer,
                buflen,
                "%s-int-x",
                info->func->namebuf
                ); 
    }
    return 0;
}
static struct irq_driver
pci_intx_irq_driver = {
    .ack_irq = pci_intx_ack_irq,
    .eoi_irq = pci_intx_eoi_irq,
    .mask_irq = pci_intx_mask_irq,
    .unmask_irq = pci_intx_unmask_irq,
    .irq_status = pci_intx_irq_status,
    .trigger_irq = pci_intx_trigger_irq,
    .describe_irq = pci_intx_describe_irq,
};

static inline int
pci_func_link_intx(
        struct pci_func *func,
        pci_intx_pin_t pin,
        irq_t irq)
{
    struct pci_intx_info *info = func->intx_info;
    if(info == NULL) {
        wprintk("pci_func_route_intx: cannot route interrupt on PCI function without INT-X initialized! (intx_info==NULL)\n");
        return -EINVAL;
    }
    struct irq_domain *domain = info->irq_domain;
    if(domain == NULL) {
        wprintk("pci_func_route_intx: cannot route interrupt on PCI function without INT-X initialized! (irq_domain==NULL)\n");
        return -EINVAL;
    }

    hwirq_t hwirq;
    switch(pin) {
        case PCI_INTX_INTA: hwirq = 1; break;
        case PCI_INTX_INTB: hwirq = 2; break;
        case PCI_INTX_INTC: hwirq = 3; break;
        case PCI_INTX_INTD: hwirq = 4; break;
        default:
            wprintk("pci_func_route_intx: cannot route invalid INT-X pin (%s)\n",
                    pci_intx_pin_to_string(pin));
            return -EINVAL;
    }

    if(info->pin_links[hwirq-1]) {
        // Remove the old link
        irq_uninstall_action(info->pin_links[hwirq-1]);
        info->pin_links[hwirq-1] = NULL;
    }

    irq_t pin_irq = irq_domain_revmap(domain, hwirq);
    if(pin_irq == NULL_IRQ) {
        wprintk("pci_func_route_intx: failed to revmap HWIRQ %d!\n",
                (int)hwirq);
        return -EINVAL;
    }

    if(irq == NULL_IRQ) {
        // Request to un-link the pin, is successful
        return 0;
    }

    // Create the link
    struct irq_action *link;
    link = irq_install_direct_link(
            irq_to_desc(irq),
            irq_to_desc(pin_irq));
    if(link == NULL) {
        wprintk("pci_func_route_intx: failed to create link from IRQ %d to IRQ %d!\n",
                (int)irq,
                (int)pin_irq);
        return -EINVAL;
    }

    info->pin_links[hwirq-1] = link;
    return 0;
}

int
pci_func_init_intx_info(struct pci_func *func)
{
    int res;

    func->intx_info = NULL;

    struct pci_intx_info *info;
    info = kzmalloc(sizeof(*info), KM_KERNEL);
    if(info == NULL) {
        return -ENOMEM;
    }
    info->func = func;

    for(int i = 0; i < 4; i++) {
        info->pin_links[i] = NULL;
    }

    uint8_t config_pin;
    res = pci_func_readb(func, PCI_CFG_IRQ_PIN, &config_pin);
    if(res) {
        kfree(info);
        return res;
    }

    switch(config_pin) {
        case 0: info->pin = PCI_INTX_NONE; break;
        case 1: info->pin = PCI_INTX_INTA; break;
        case 2: info->pin = PCI_INTX_INTB; break;
        case 3: info->pin = PCI_INTX_INTC; break;
        case 4: info->pin = PCI_INTX_INTD; break;
        default:
            kfree(info);
            return -EINVAL;
    }

    printk("PCI Function Setup INT-X (%s)\n",
            pci_intx_pin_to_string(info->pin));

    info->irq_domain = alloc_irq_domain_linear(0, 5);
    if(info->irq_domain == NULL) {
        kfree(info);
        return -ENOMEM;
    }

    if(info->pin != PCI_INTX_NONE) {
        irq_t active_irq = irq_domain_revmap(info->irq_domain, 0);
        irq_t pin_irq = irq_domain_revmap(info->irq_domain, info->pin);
        info->active_link = irq_install_direct_link(irq_to_desc(pin_irq), irq_to_desc(active_irq));
    }

    info->irq_dev.driver = &pci_intx_irq_driver;
    res = register_irq_dev(
            &info->irq_dev,
            func->namebuf);
    if(res) {
        free_irq_domain_linear(info->irq_domain);
        kfree(info);
        return res;
    }

    res = irq_domain_set_all_irq_dev(info->irq_domain, &info->irq_dev);
    if(res) {
        unregister_irq_dev(&info->irq_dev);
        free_irq_domain_linear(info->irq_domain);
        kfree(info);
        return res;
    }

    func->intx_info = info;
    return 0;
}

int
pci_func_deinit_intx_info(struct pci_func *func)
{
    struct pci_intx_info *info = func->intx_info;
    if(info == NULL) {
        return -EINVAL;
    }
    func->intx_info = NULL;

    if(info->active_link != NULL) {
        irq_uninstall_action(info->active_link);
    }
    for(int i = 0; i < 4; i++) {
        if(info->pin_links[i] != NULL) {
            irq_uninstall_action(info->pin_links[i]);
        }
    }

    unregister_irq_dev(&info->irq_dev);
    free_irq_domain_linear(info->irq_domain);
    kfree(info);
    return 0;
}

int
pci_func_start_intx(struct pci_func *func, size_t req_num_irqs)
{
    int res;

    res = pci_func_link_intx(func, PCI_INTX_INTA, func->intx_routing[0]);
    if(res) {return res;}
    res = pci_func_link_intx(func, PCI_INTX_INTB, func->intx_routing[1]);
    if(res) {return res;}
    res = pci_func_link_intx(func, PCI_INTX_INTC, func->intx_routing[2]);
    if(res) {return res;}
    res = pci_func_link_intx(func, PCI_INTX_INTD, func->intx_routing[3]);
    if(res) {return res;}

    func->irq_domain = func->intx_info->irq_domain;
    res = pci_func_raw_enable_intx(func);
    if(res) {
        return res;
    }

    return 0;
}
int
pci_func_stop_intx(struct pci_func *func)
{
    int res;
    func->irq_domain = NULL;
    res = pci_func_raw_disable_intx(func);
    if(res) {
        return res;
    }
    return 0;
}

int
pci_func_route_intx(
        struct pci_func *func,
        pci_intx_pin_t pin,
        irq_t irq)
{
    int res;

    size_t index;
    switch(pin)
    {
        case PCI_INTX_INTA: index = 0; break;
        case PCI_INTX_INTB: index = 1; break;
        case PCI_INTX_INTC: index = 2; break;
        case PCI_INTX_INTD: index = 3; break;
        default:
            return -EINVAL;
    }
    func->intx_routing[index] = irq;

    if(func->irq_mode == PCI_IRQ_MODE_INTX) {
        res = pci_func_link_intx(func, pin, irq);
        if(res) {
            return res;
        }
    }

    return 0;
}
