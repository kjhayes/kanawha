
#include <drivers/pci/cap.h>
#include <drivers/pci/mailbox.h>
#include <drivers/pci/msi.h>
#include <drivers/pci/pci.h>
#include <kanawha/dev/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

static struct irq_driver msi_irq_driver;

#define MSI_DEV_NAMEBUFLEN (32)

struct msi_irq_dev
{
    struct pci_func *func;

    size_t num_irqs;
    struct irq_action **link_actions;

    struct irq_dev irq_dev;

    char namebuf[MSI_DEV_NAMEBUFLEN];
};

static inline uint16_t
pci_msi_read_msg_ctrl(struct pci_func *func, struct pci_msi_info *info)
{
    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    return msg_ctrl;
}

static inline int
pci_msi_write_msg_ctrl(struct pci_func *func,
                       struct pci_msi_info *info,
                       uint16_t msg_ctrl)
{
    return pci_cap_writew(func, info->cap, 0x2, msg_ctrl);
}

// init
int
pci_func_init_msi_info(struct pci_func *func)
{
    struct pci_cap *cap = pci_func_find_cap(func, PCI_CAP_ID_MSI);
    if(cap == NULL)
    {
        func->msi_info = NULL;
        return 0;
    }

    struct pci_msi_info *info =
        kzmalloc(sizeof(struct pci_msi_info), KM_KERNEL);
    if(info == NULL)
    {
        return -ENOMEM;
    }

    info->cap = cap;

    func->msi_info = info;
    printk("PCI Function has MSI Capability\n");

    return 0;
}

// deinit
int
pci_func_deinit_msi_info(struct pci_func *func)
{
    if(func->msi_info)
    {
        kfree(func->msi_info);
        func->msi_info = NULL;
    }
    return 0;
}

int
pci_func_start_msi(struct pci_func *func, size_t requested_num_irqs)
{
    int res;

    if(func->irq_mode != PCI_IRQ_MODE_NONE)
    {
        return -EEXIST;
    }
    if(func->irq_domain != NULL)
    {
        return -EEXIST;
    }

    struct pci_msi_info *info = func->msi_info;
    if(info == NULL)
    {
        return -ENXIO;
    }

    struct msi_irq_dev *msi_dev =
        kzmalloc(sizeof(struct msi_irq_dev), KM_KERNEL);
    if(msi_dev == NULL)
    {
        return -ENOMEM;
    }

    msi_dev->func = func;

    {
        snprintk(msi_dev->namebuf,
                 MSI_DEV_NAMEBUFLEN,
                 "msi-%d.%d.%d.%d",
                 (int)func->segment->segment_id,
                 (int)func->device->bus->bus_index,
                 (int)func->device->index,
                 (int)func->index);
        msi_dev->namebuf[MSI_DEV_NAMEBUFLEN - 1] = '\0';
    }

    msi_dev->irq_dev.driver = &msi_irq_driver;
    res = register_irq_dev(&msi_dev->irq_dev, msi_dev->namebuf);
    if(res)
    {
        kfree(msi_dev);
        return res;
    }

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    msg_ctrl &= ~(1ULL << 0); // Disable MSI before we start configuring
    pci_msi_write_msg_ctrl(func, info, msg_ctrl);

    msi_dev->num_irqs = pci_func_msi_max_num_irqs(func);
    if(msi_dev->num_irqs == 0)
    {
        kfree(msi_dev);
        return -EINVAL;
    }

    // Enable as many IRQ's as possible (MME=MMC)
    msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    msg_ctrl &= ~(0b111ULL << 4);
    msg_ctrl |= (((msg_ctrl >> 1) & 0b111ULL) << 4);
    pci_msi_write_msg_ctrl(func, info, msg_ctrl);

    msi_dev->link_actions =
        kzmalloc(sizeof(struct irq_action *) * msi_dev->num_irqs, KM_KERNEL);
    if(msi_dev->link_actions == NULL)
    {
        unregister_irq_dev(&msi_dev->irq_dev);
        func->irq_dev = NULL;
        kfree(msi_dev);
        return -ENOMEM;
    }

    struct irq_desc *descs[msi_dev->num_irqs];
    memset(descs, 0, sizeof(struct irq_desc *) * msi_dev->num_irqs);

    msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    if(msg_ctrl & (1ULL << 7))
    {
        // 64-bit
        uint16_t msg_data;
        uint64_t addr;
        res =
            pci_mailbox_find_msi64(msi_dev->num_irqs, &addr, &msg_data, descs);
        if(res)
        {
            unregister_irq_dev(&msi_dev->irq_dev);
            func->irq_dev = NULL;
            kfree(msi_dev->link_actions);
            kfree(msi_dev);
            return res;
        }

        pci_cap_writel(func, info->cap, 0x4, addr & 0xFFFFFFFF);
        pci_cap_writel(func, info->cap, 0x8, (addr >> 32) & 0xFFFFFFFF);
        pci_cap_writew(func, info->cap, 0xC, msg_data);
    }
    else
    {
        // 32-bit
        uint16_t msg_data;
        uint32_t addr;
        res =
            pci_mailbox_find_msi32(msi_dev->num_irqs, &addr, &msg_data, descs);
        if(res)
        {
            unregister_irq_dev(&msi_dev->irq_dev);
            func->irq_dev = NULL;
            kfree(msi_dev->link_actions);
            kfree(msi_dev);
            return res;
        }

        pci_cap_writel(func, info->cap, 0x4, addr & 0xFFFFFFFF);
        pci_cap_writew(func, info->cap, 0x8, msg_data);
    }

    struct irq_domain *domain = alloc_irq_domain_linear(0, msi_dev->num_irqs);
    if(domain == NULL)
    {
        unregister_irq_dev(&msi_dev->irq_dev);
        func->irq_dev = NULL;
        kfree(msi_dev->link_actions);
        kfree(msi_dev);
        return -ENOMEM;
    }

    res = irq_domain_set_all_irq_dev(domain, &msi_dev->irq_dev);
    if(res)
    {
        unregister_irq_dev(&msi_dev->irq_dev);
        func->irq_dev = NULL;
        free_irq_domain_linear(domain);
        kfree(msi_dev->link_actions);
        kfree(msi_dev);
        return res;
    }

    // Install IRQ Links from Mailbox to MSI IRQ Domain
    {
        int failed_link = 0;
        for(size_t i = 0; i < msi_dev->num_irqs; i++)
        {
            struct irq_desc *link_from = descs[i];
            irq_t link_to_irq = irq_domain_revmap(domain, i);
            if(link_to_irq == NULL_IRQ)
            {
                failed_link = 1;
                break;
            }
            struct irq_desc *link_to = irq_to_desc(link_to_irq);
            if(link_to == NULL)
            {
                failed_link = 1;
                break;
            }

            msi_dev->link_actions[i] =
                irq_install_direct_link(link_from, link_to);
            if(msi_dev->link_actions[i] == NULL)
            {
                failed_link = 1;
                break;
            }
        }

        if(failed_link)
        {
            unregister_irq_dev(&msi_dev->irq_dev);
            func->irq_dev = NULL;
            for(size_t i = 0; i < msi_dev->num_irqs; i++)
            {
                if(msi_dev->link_actions[i] != NULL)
                {
                    irq_uninstall_action(msi_dev->link_actions[i]);
                }
            }
            free_irq_domain_linear(domain);
            kfree(msi_dev->link_actions);
            kfree(msi_dev);
            return -EINVAL;
        }
    }

    pci_func_raw_disable_intx(func);
    pci_func_raw_enable_bus_master(func);
    pci_func_raw_enable_mmio(func);

    msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    msg_ctrl |= (1ULL << 0);
    pci_msi_write_msg_ctrl(func, info, msg_ctrl);

    func->irq_mode = PCI_IRQ_MODE_MSI;
    func->irq_dev = &msi_dev->irq_dev;
    func->irq_domain = domain;

    return 0;
}

int
pci_func_stop_msi(struct pci_func *func)
{
    if(func->irq_mode != PCI_IRQ_MODE_MSI)
    {
        return -EINVAL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(func->irq_dev));
    DEBUG_ASSERT(KERNEL_ADDR(func->irq_domain));
    DEBUG_ASSERT(KERNEL_ADDR(func->msi_info));

    struct msi_irq_dev *msi_dev =
        container_of(func->irq_dev, struct msi_irq_dev, irq_dev);

    for(size_t i = 0; i < msi_dev->num_irqs; i++)
    {
        if(msi_dev->link_actions[i] != NULL)
        {
            irq_uninstall_action(msi_dev->link_actions[i]);
            msi_dev->link_actions[i] = NULL;
        }
    }

    free_irq_domain_linear(func->irq_domain);

    unregister_irq_dev(&msi_dev->irq_dev);

    kfree(msi_dev->link_actions);
    kfree(msi_dev);

    func->irq_domain = NULL;
    func->irq_dev = NULL;
    func->irq_mode = PCI_IRQ_MODE_NONE;

    return 0;
}

// max_irqs
size_t
pci_func_msi_max_num_irqs(struct pci_func *func)
{
    struct pci_msi_info *info = func->msi_info;
    if(info == NULL)
    {
        return 0;
    }

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    uint8_t mmc = (msg_ctrl >> 1) & 0b111;
    return 1ULL << mmc;
}

size_t
pci_func_msi_num_irqs(struct pci_func *func)
{
    struct pci_msi_info *info = func->msi_info;
    if(info == NULL)
    {
        return 0;
    }

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, info);
    uint8_t mme = (msg_ctrl >> 4) & 0b111;
    return 1ULL << mme;
}

static int
msi_mask_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    struct msi_irq_dev *msi_dev =
        container_of(dev, struct msi_irq_dev, irq_dev);
    struct pci_func *func = msi_dev->func;

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, func->msi_info);
    if(msg_ctrl & (1ULL << 7))
    {
        uint32_t mask = pci_cap_readl(func, func->msi_info->cap, 0x10);
        mask |= (1ULL << hwirq);
        pci_cap_writel(func, func->msi_info->cap, 0x10, mask);
        return 0;
    }
    else
    {
        // Cannot mask IRQ's with 32-bit MSI Address
        return -EINVAL;
    }
}

static int
msi_unmask_irq(struct irq_dev *dev, hwirq_t hwirq)
{
    struct msi_irq_dev *msi_dev =
        container_of(dev, struct msi_irq_dev, irq_dev);
    struct pci_func *func = msi_dev->func;

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, func->msi_info);
    if(msg_ctrl & (1ULL << 7))
    {
        uint32_t mask = pci_cap_readl(func, func->msi_info->cap, 0x10);
        mask &= ~(1ULL << hwirq);
        pci_cap_writel(func, func->msi_info->cap, 0x10, mask);
        return 0;
    }
    else
    {
        // 32-Bit MSI is always unmasked
        return 0;
    }
}

static unsigned long
msi_irq_status(struct irq_dev *dev, hwirq_t hwirq)
{
    struct msi_irq_dev *msi_dev =
        container_of(dev, struct msi_irq_dev, irq_dev);
    struct pci_func *func = msi_dev->func;

    unsigned long flags = 0;

    uint16_t msg_ctrl = pci_msi_read_msg_ctrl(func, func->msi_info);
    if(msg_ctrl & (1ULL << 7))
    {
        uint32_t mask = pci_cap_readl(func, func->msi_info->cap, 0x10);
        if(mask & (1ULL << hwirq))
        {
            flags |= IRQ_STATUS_MASKED;
        }
    }
    else
    {
        // 32-Bit MSI is always unmasked
    }

    return flags;
}

static int
msi_describe_irq(struct irq_dev *dev,
                 hwirq_t hwirq,
                 char *buffer,
                 size_t buflen)
{
    struct msi_irq_dev *msi_dev =
        container_of(dev, struct msi_irq_dev, irq_dev);
    struct pci_func *func = msi_dev->func;

    snprintk(buffer,
             buflen,
             "msi-%lu.%lu",
             (ul_t)func->device->index,
             (ul_t)func->index);

    return 0;
}

static struct irq_driver msi_irq_driver = {
    .mask_irq = msi_mask_irq,
    .unmask_irq = msi_unmask_irq,
    .irq_status = msi_irq_status,
    .describe_irq = msi_describe_irq,
};
