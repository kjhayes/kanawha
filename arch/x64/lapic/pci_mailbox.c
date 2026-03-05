
#include <arch/x64/lapic.h>
#include <arch/x64/lapic/pci_mailbox.h>
#include <drivers/pci/mailbox.h>
#include <kanawha/stddef.h>

static inline uint32_t
lapic_msi_msg_addr(struct lapic *lapic)
{
    uint32_t redirection_hint = 0; // Hard-code both of these bits to zero
    uint32_t destination_mode = 0;

    return 0xFEE00000ULL | ((lapic->id & 0xFF) << 12) |
           (redirection_hint << 3) | (destination_mode << 2);
}

static inline uint16_t
lapic_msi_msg_data(struct lapic *lapic, uint8_t vector)
{
    return (uint16_t)vector & 0xFF;
}

static int
lapic_msi_req_32(struct pci_mailbox *mb,
                 size_t num_req,
                 uint32_t *addr,
                 uint16_t *data)
{
    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    *addr = lapic_msi_msg_addr(lapic);
    *data = lapic_msi_msg_data(lapic, 32); // TODO: Don't set every
                                           //       MSI Interrupt Block to
                                           //       start at IRQ 32...

    return 0;
}

static int
lapic_msi_req_64(struct pci_mailbox *mb,
                 size_t num_req,
                 uint64_t *addr,
                 uint16_t *data)
{
    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    *addr = (uint64_t)lapic_msi_msg_addr(lapic) & 0xFFFFFFFFULL;
    *data = lapic_msi_msg_data(lapic, 32); // TODO: Don't set every
                                           //       MSI Interrupt Block to
                                           //       start at IRQ 32...

    return 0;
}

static int
lapic_msix_req(struct pci_mailbox *mb,
               size_t num_req,
               uint64_t *addrs,
               uint32_t *datas)
{
    if(num_req > 256 - 32)
    {
        return -EINVAL;
    }

    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    for(size_t i = 0; i < num_req; i++)
    {
        hwirq_t hwirq = lapic->pci_mailbox_next_to_give;
        addrs[i] = (uint64_t)lapic_msi_msg_addr(lapic) & 0xFFFFFFFFULL;
        datas[i] = lapic_msi_msg_data(lapic, hwirq);
        if(lapic->pci_mailbox_next_to_give < 248)
        {
            lapic->pci_mailbox_next_to_give++;
        }
        else
        {
            lapic->pci_mailbox_next_to_give = 32;
        }
    }

    return 0;
}

static struct irq_desc *
lapic_msi_get_desc_32(struct pci_mailbox *mb,
                      uint32_t addr,
                      uint16_t data,
                      size_t index)
{
    hwirq_t base_hwirq = data & 0xFF;
    hwirq_t hwirq = base_hwirq + index;

    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    irq_t irq = irq_domain_revmap(lapic->irq_domain, hwirq);
    if(irq == NULL_IRQ)
    {
        return NULL;
    }
    return irq_to_desc(irq);
}

static struct irq_desc *
lapic_msi_get_desc_64(struct pci_mailbox *mb,
                      uint64_t addr,
                      uint16_t data,
                      size_t index)
{
    hwirq_t base_hwirq = data & 0xFF;
    hwirq_t hwirq = base_hwirq + index;

    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    irq_t irq = irq_domain_revmap(lapic->irq_domain, hwirq);
    if(irq == NULL_IRQ)
    {
        return NULL;
    }
    return irq_to_desc(irq);
}

static struct irq_desc *
lapic_msix_get_desc(struct pci_mailbox *mb,
                    uint64_t addr,
                    uint32_t data,
                    size_t index)
{
    hwirq_t hwirq = data & 0xFF;

    struct lapic *lapic = container_of(mb, struct lapic, pci_mailbox);

    irq_t irq = irq_domain_revmap(lapic->irq_domain, hwirq);
    if(irq == NULL_IRQ)
    {
        return NULL;
    }
    return irq_to_desc(irq);
}

struct pci_mailbox_ops lapic_pci_mailbox_ops = {
    .msi_req_32 = lapic_msi_req_32,
    .msi_req_64 = lapic_msi_req_64,
    .msix_req = lapic_msix_req,

    .msi_get_desc_32 = lapic_msi_get_desc_32,
    .msi_get_desc_64 = lapic_msi_get_desc_64,
    .msix_get_desc = lapic_msix_get_desc,
};

int
register_cpu_lapic_pci_mailbox(struct lapic *lapic)
{
    int res;
    lapic->pci_mailbox_next_to_give = 32;
    res = register_pci_mailbox(&lapic->pci_mailbox, &lapic_pci_mailbox_ops);
    if(res)
    {
        return res;
    }
    return 0;
}
