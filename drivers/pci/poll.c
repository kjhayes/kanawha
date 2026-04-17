
#include <drivers/pci/mailbox.h>
#include <kanawha/dma.h>
#include <kanawha/lock.h>
#include <kanawha/event.h>

typedef uint32_t poll_box_t;

struct polling_pci_mailbox {
    struct pci_mailbox mailbox;

    size_t num_irqs;
    struct irq_domain *domain;

    dma_addr_t boxes;

    struct periodic_event *poll;
};

static void
polling_pci_mailbox_handle_pending(void *_mb)
{
    int res;

    struct polling_pci_mailbox *mb = _mb;
    poll_box_t *boxes = dma_virt_addr(mb->boxes);
    for(hwirq_t hwirq = 0; hwirq < mb->num_irqs; hwirq++) {
        if(!boxes[hwirq]) {
            continue;
        }

        irq_t irq = irq_domain_revmap(mb->domain, hwirq);
        if(irq == NULL_IRQ) {
            boxes[hwirq] = 0;
            continue;
        }

        struct irq_desc *desc = irq_to_desc(irq);
        if(desc == NULL) {
            boxes[hwirq] = 0;
            continue;
        }

        printk("polling_pci_mailbox: HIT!\n");
        res = handle_irq(desc, NULL);
        if(res == IRQ_UNHANDLED) {
            wprintk("polling_pci_mailbox: unhandled IRQ!\n");
        }

        boxes[hwirq] = 0;
    }
}

static int
polling_msi_req_32(
        struct pci_mailbox *pci_mb,
        size_t num_req,
        uint32_t *addr_out,
        uint16_t *data_out)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes);

    if((void __phys *)(p_boxes + mb->num_irqs) >= (void __phys *)0x100000000ULL) {
        return -EINVAL;
    }

    if(num_req > mb->num_irqs) {
        return -EINVAL;
    }

    *addr_out = (uint32_t)(uintptr_t)p_boxes;
    *data_out = 0x1;

    return 0;
}

static int
polling_msi_req_64(
        struct pci_mailbox *pci_mb,
        size_t num_req,
        uint64_t *addr_out,
        uint16_t *data_out)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes); 

    if(num_req > mb->num_irqs) {
        return -EINVAL;
    }

    *addr_out = (uint64_t)p_boxes;
    *data_out = 0x1;

    return 0;
}

static int
polling_msix_req(
        struct pci_mailbox *pci_mb,
        size_t num_req,
        uint64_t *addrs_out,
        uint32_t *datas_out)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes); 

    if(num_req > mb->num_irqs) {
        return -EINVAL;
    }

    for(size_t hwirq = 0; hwirq < num_req; hwirq++) {
        addrs_out[hwirq] = (uint64_t)(p_boxes + hwirq);
        datas_out[hwirq] = 0x1;
    }

    return 0;
}

static struct irq_desc *
polling_msi_get_desc_32(
        struct pci_mailbox *pci_mb,
        uint32_t addr,
        uint16_t data,
        size_t index)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    DEBUG_ASSERT(data == 0x1);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes); 
    size_t byte_offset = ((void __phys *)(uintptr_t)addr) - ((void __phys *)p_boxes);

    hwirq_t hwirq = byte_offset / sizeof(poll_box_t);
    hwirq += index;
    if(hwirq >= mb->num_irqs) {
        return NULL;
    }

    irq_t irq = irq_domain_revmap(mb->domain, hwirq);
    if(irq == NULL_IRQ) {
        return NULL;
    }

    return irq_to_desc(irq);
}

static struct irq_desc *
polling_msi_get_desc_64(
        struct pci_mailbox *pci_mb,
        uint64_t addr,
        uint16_t data,
        size_t index)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    DEBUG_ASSERT(data == 0x1);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes); 
    size_t byte_offset = ((void __phys *)(uintptr_t)addr) - ((void __phys *)p_boxes);

    hwirq_t hwirq = byte_offset / sizeof(poll_box_t);
    hwirq += index;
    if(hwirq >= mb->num_irqs) {
        return NULL;
    }

    irq_t irq = irq_domain_revmap(mb->domain, hwirq);
    if(irq == NULL_IRQ) {
        return NULL;
    }

    return irq_to_desc(irq);
}

static struct irq_desc *
polling_msix_get_desc(
        struct pci_mailbox *pci_mb,
        uint64_t addr,
        uint32_t data,
        size_t index)
{
    struct polling_pci_mailbox *mb
        = container_of(pci_mb, struct polling_pci_mailbox, mailbox);

    DEBUG_ASSERT(data == 0x1);

    poll_box_t __phys *p_boxes = dma_phys_addr(mb->boxes); 
    size_t byte_offset = ((void __phys *)addr) - ((void __phys *)p_boxes);

    hwirq_t hwirq = byte_offset / sizeof(poll_box_t);
    hwirq += index;
    if(hwirq >= mb->num_irqs) {
        return NULL;
    }

    irq_t irq = irq_domain_revmap(mb->domain, hwirq);
    if(irq == NULL_IRQ) {
        return NULL;
    }

    return irq_to_desc(irq);
}

static struct pci_mailbox_ops
polling_pci_mailbox_ops = {
    .msi_req_32 = polling_msi_req_32,
    .msi_req_64 = polling_msi_req_64,
    .msix_req = polling_msix_req,
    .msi_get_desc_32 = polling_msi_get_desc_32,
    .msi_get_desc_64 = polling_msi_get_desc_64,
    .msix_get_desc = polling_msix_get_desc,
};

static struct polling_pci_mailbox *
create_polling_pci_mailbox(
        size_t num_irqs)
{
    int res;

    struct polling_pci_mailbox *mb =
        kzmalloc(sizeof(*mb), KM_KERNEL);
    if(mb == NULL) {
        return NULL;
    }

    mb->num_irqs = num_irqs;

    res = dma_alloc(
            sizeof(poll_box_t) * num_irqs,
            orderof(poll_box_t),
            DMA_PHYS_64,
            &mb->boxes);
    if(res) {
        kfree(mb);
        return NULL;
    }

    { // Zero all of the poll boxes
        void *box_data = dma_virt_addr(mb->boxes);
        memset(box_data, 0, sizeof(poll_box_t) * num_irqs);
    }

    mb->domain = alloc_irq_domain_linear(0, num_irqs);
    if(mb->domain == NULL) {
        dma_free(mb->boxes, num_irqs * sizeof(poll_box_t));
        kfree(mb);
        return NULL;
    }

    mb->mailbox.ops = &polling_pci_mailbox_ops;

    mb->poll = create_periodic_event(
            msec_to_duration(10),
            mb,
            polling_pci_mailbox_handle_pending);
    if(mb->poll == NULL) {
        free_irq_domain_linear(mb->domain);
        dma_free(mb->boxes, num_irqs * sizeof(poll_box_t));
        kfree(mb);
        return NULL;
    }

    res = register_pci_mailbox(
            &mb->mailbox,
            &polling_pci_mailbox_ops);
    if(res) {
        destroy_periodic_event(mb->poll);
        free_irq_domain_linear(mb->domain);
        dma_free(mb->boxes, num_irqs * sizeof(poll_box_t));
        kfree(mb);
        return NULL;
    }

    return mb;
}

static struct polling_pci_mailbox *__mb = NULL;
static inline int
init_polling_pci_mailbox(void)
{
    __mb = create_polling_pci_mailbox(0x1000);
    if(__mb == NULL) {
        eprintk("Failed to register polling PCI mailbox!\n");
        return -ENOMEM;
    }
    return 0;
}
declare_init_desc(bus, init_polling_pci_mailbox, "Providing Polling PCI Mailbox");

