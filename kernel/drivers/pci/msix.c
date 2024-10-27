
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <drivers/pci/msix.h>
#include <drivers/pci/mailbox.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

static struct irq_dev_driver msix_irq_driver;

struct msix_irq_dev
{
    struct pci_func *func;

    size_t num_irqs;
    struct irq_action **link_actions;

    struct irq_dev irq_dev;
};

static inline uint16_t
pci_msix_read_msg_ctrl(
        struct pci_func *func,
        struct pci_msix_info *info)
{
    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    return msg_ctrl;
}

static inline int
pci_msix_write_msg_ctrl(
        struct pci_func *func,
        struct pci_msix_info *info,
        uint16_t msg_ctrl)
{
    return pci_cap_writew(func, info->cap, 0x2, msg_ctrl);
}

static inline int
pci_msix_bir_writel(
        struct pci_func *func,
        struct pci_msix_info *info,
        uint32_t offset,
        uint32_t value)
{
    pci_bar_writel(
            info->bir,
            offset,
            value);
    return 0;
}

static inline uint32_t
pci_msix_bir_readl(
        struct pci_func *func,
        struct pci_msix_info *info,
        uint32_t offset)
{
    return pci_bar_readl(
            info->bir,
            offset);
}

static inline int
pci_msix_bir_write_addr(
        struct pci_func *func,
        struct pci_msix_info *info,
        hwirq_t hwirq,
        uint64_t addr)
{
    int res;
    res = pci_msix_bir_writel(
            func,
            info,
            (hwirq * 0x10) + 0x0,
            addr & 0xFFFFFFFFULL);
    if(res) {
        return res;
    }
    res = pci_msix_bir_writel(
            func,
            info,
            (hwirq * 0x10) + 0x4,
            (addr>>32) & 0xFFFFFFFFULL);
    if(res) {
        return res;
    }

    return 0;
}

static inline int
pci_msix_bir_write_data(
        struct pci_func *func,
        struct pci_msix_info *info,
        hwirq_t hwirq,
        uint32_t data)
{
    return pci_msix_bir_writel(
            func,
            info,
            (hwirq * 0x10) + 0x8,
            data);
}

static inline int
pci_msix_bir_mask(
        struct pci_func *func,
        struct pci_msix_info *info,
        hwirq_t hwirq)
{
    uint32_t original = pci_msix_bir_readl(
            func,
            info,
            (hwirq * 0x10) + 0xC);
    return pci_msix_bir_writel(
            func,
            info,
            (hwirq * 0x10) + 0xC,
            original | 1ULL);
}

static inline int
pci_msix_bir_unmask(
        struct pci_func *func,
        struct pci_msix_info *info,
        hwirq_t hwirq)
{
    uint32_t original = pci_msix_bir_readl(
            func,
            info,
            (hwirq * 0x10) + 0xC);
    return pci_msix_bir_writel(
            func,
            info,
            (hwirq * 0x10) + 0xC,
            original & ~1ULL);
}

int
pci_func_init_msix_info(
        struct pci_func *func)
{
    struct pci_cap *cap = pci_func_find_cap(func, 0x11);
    if(cap == NULL) {
        func->msix_info = NULL;
        return 0;
    }

    struct pci_msix_info *info = kmalloc(sizeof(struct pci_msix_info));
    if(info == NULL) {
        return -ENOMEM;
    }
    memset(info, 0, sizeof(struct pci_msix_info));

    info->cap = cap;

    uint32_t bir_info = pci_cap_readb(func, cap, 0x4);
    uint8_t bir = bir_info & 0xFF;
    uint32_t bir_offset = bir_info & 0xFFFFFF00;

    if(bir >= 6) {
        return -EINVAL;
    }
    if(func->bars[bir].type != PCI_BAR_MMIO) {
        return -EINVAL;
    }
    info->bir = &func->bars[bir];
    info->bir_offset = bir_offset;

    uint32_t pending_bir_info = pci_cap_readb(func, cap, 0x8);
    uint8_t pending_bir = pending_bir_info & 0xFF;
    uint32_t pending_bir_offset = pending_bir_info & 0xFFFFFF00;
    if(pending_bir >= 6) {
        return -EINVAL;
    }
    if(func->bars[pending_bir].type != PCI_BAR_MMIO) {
        return -EINVAL;
    }
    info->pending_bir = &func->bars[bir];
    info->pending_bir_offset = pending_bir_offset;

    func->msix_info = info;
    printk("PCI Function has MSI-X Capability (BIR=0x%x, BIR-OFFSET=0x%x)\n",
            bir, bir_offset);

    return 0;
}

int
pci_func_deinit_msix_info(
        struct pci_func *func)
{
    if(func->msix_info) {
        kfree(func->msix_info);
        func->msix_info = NULL;
    }
    return 0;
}

size_t
pci_func_msix_num_irqs(
        struct pci_func *func)
{
    struct pci_msix_info *info = func->msix_info;
    if(info == NULL) {
        return 0;
    }

    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    uint16_t table_size = (msg_ctrl & ((1ULL<<11)-1)) + 1;
    return table_size;
}

int
pci_func_start_msix(struct pci_func *func)
{
    int res;

    if(func->irq_mode != PCI_IRQ_MODE_NONE) {
        return -EEXIST;
    }
    if(func->irq_domain != NULL) {
        return -EEXIST;
    }

    struct pci_msix_info *info = func->msix_info;
    if(info == NULL) {
        return -EINVAL;
    }

    struct msix_irq_dev *msix_dev = kmalloc(sizeof(struct msix_irq_dev));
    if(msix_dev == NULL) {
        return -ENOMEM;
    }
    memset(msix_dev, 0, sizeof(struct msix_irq_dev));

    uint16_t msg_ctrl = pci_msix_read_msg_ctrl(func, info);
    msg_ctrl &= ~(1ULL<<15); // Disable MSI-X before we start configuring
    pci_msix_write_msg_ctrl(func, info, msg_ctrl);

    msix_dev->irq_dev.driver = &msix_irq_driver;
    msix_dev->num_irqs = pci_func_msix_num_irqs(func);
    if(msix_dev->num_irqs == 0) {
        kfree(msix_dev);
        return -EINVAL;
    }

    uint64_t addrs[msix_dev->num_irqs];
    memset(addrs, 0, sizeof(uint64_t) * msix_dev->num_irqs);
    uint32_t datas[msix_dev->num_irqs];
    memset(addrs, 0, sizeof(uint32_t) * msix_dev->num_irqs);
    struct irq_desc *descs[msix_dev->num_irqs];
    memset(descs, 0, sizeof(struct irq_desc*) * msix_dev->num_irqs);
    res = pci_mailbox_find_msix(
        msix_dev->num_irqs,
        addrs,
        datas,
        descs);
    if(res) {
        kfree(msix_dev);
        return res;
    }

    for(size_t i = 0; i < msix_dev->num_irqs; i++) {
        uint64_t addr = addrs[i];
        uint32_t data = datas[i];
        pci_msix_bir_write_addr(func, info, i, addr);
        pci_msix_bir_write_data(func, info, i, data);
        pci_msix_bir_mask(func, info, i);
    }

    msix_dev->link_actions = kmalloc(sizeof(struct irq_action*) * msix_dev->num_irqs);
    if(msix_dev->link_actions == NULL) {
        kfree(msix_dev);
        return -ENOMEM;
    }
    memset(msix_dev->link_actions, 0, sizeof(struct irq_action*) * msix_dev->num_irqs);

    struct irq_domain *domain =
        alloc_irq_domain_linear(0, msix_dev->num_irqs);
    if(domain == NULL) {
        kfree(msix_dev->link_actions);
        kfree(msix_dev);
        return -ENOMEM;
    }

    int failed_link = 0;
    for(size_t i = 0; i < msix_dev->num_irqs; i++) {
        struct irq_desc *link_from = descs[i];
        irq_t link_to_irq = irq_domain_revmap(domain, i);
        if(link_to_irq == NULL_IRQ) {
            failed_link = 1;
            break;
        }
        struct irq_desc *link_to = irq_to_desc(link_to_irq);
        if(link_to == NULL) {
            failed_link = 1;
            break;
        }

        msix_dev->link_actions[i] = irq_install_direct_link(link_from, link_to);
        if(msix_dev->link_actions[i] == NULL) {
            failed_link = 1;
            break;
        }
    }

    if(failed_link) {
        for(size_t i = 0; i < msix_dev->num_irqs; i++) {
            if(msix_dev->link_actions[i] != NULL) {
                irq_uninstall_action(msix_dev->link_actions[i]);
                msix_dev->link_actions[i] = NULL;
            }
        }
        kfree(msix_dev->link_actions);
        kfree(msix_dev);
        return -EINVAL;
    }

    pci_func_raw_disable_intx(func);
    pci_func_raw_enable_bus_master(func);
    pci_func_raw_enable_mmio(func);

    msg_ctrl = pci_msix_read_msg_ctrl(func, info);
    msg_ctrl |= (1ULL<<15);
    pci_msix_write_msg_ctrl(func, info, msg_ctrl);

    func->irq_mode = PCI_IRQ_MODE_MSIX;
    func->irq_dev = &msix_dev->irq_dev;
    func->irq_domain = domain;

    return 0;
}

int
pci_func_stop_msix(struct pci_func *func)
{
    return -EUNIMPL;
}

static int
msix_mask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    struct msix_irq_dev *msix_dev =
        container_of(dev, struct msix_irq_dev, irq_dev);
    struct pci_func *func = msix_dev->func;
    struct pci_msix_info *info = func->msix_info;

    return pci_msix_bir_mask(func, info, hwirq);
}

static int
msix_unmask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    struct msix_irq_dev *msix_dev =
        container_of(dev, struct msix_irq_dev, irq_dev);
    struct pci_func *func = msix_dev->func;
    struct pci_msix_info *info = func->msix_info;

    return pci_msix_bir_unmask(func, info, hwirq);
}

static struct irq_dev_driver
msix_irq_driver = {
    .ack_irq = NULL,
    .eoi_irq = NULL,
    .mask_irq = msix_unmask_irq,
    .unmask_irq = msix_mask_irq,
    .trigger_irq = NULL,
};

