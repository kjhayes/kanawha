
#include <arch/x64/ioapic.h>
#include <arch/x64/exception.h>
#include <arch/x64/lapic.h>
#include <arch/x64/cpu.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/spinlock.h>
#include <kanawha/mmio.h>
#include <kanawha/device.h>
#include <kanawha/irq_dev.h>
#include <kanawha/assert.h>

static DECLARE_SPINLOCK(ioapic_list_lock);
static DECLARE_ILIST(ioapic_list);

#define IOAPIC_MMIO_SIZE 0x20

#define IOAPIC_IOREGSEL_OFFSET 0x00
#define IOAPIC_IOWIN_OFFSET    0x10

uint32_t
ioapic_read_reg(
        struct ioapic *ioapic,
        uint8_t reg_index)
{
    mmio_writel(ioapic->ioregsel, reg_index);
    return mmio_readl(ioapic->iowin);
}

void
ioapic_write_reg(
        struct ioapic *ioapic,
        uint8_t reg_index,
        uint32_t value)
{
    mmio_writel(ioapic->ioregsel, reg_index);
    mmio_writel(ioapic->iowin, value);
}

uint64_t
ioapic_read_iored(
        struct ioapic *ioapic,
        hwirq_t irq)
{
    size_t irq_offset = irq - ioapic->base_irq;
    uint32_t low, high;

    mmio_writel(ioapic->ioregsel, IOAPIC_REG_IOREDTBL_BASE + (irq_offset * 2));
    low = mmio_readl(ioapic->iowin);

    mmio_writel(ioapic->ioregsel, IOAPIC_REG_IOREDTBL_BASE + (irq_offset * 2) + 1);
    high = mmio_readl(ioapic->iowin);

    return (((uint64_t)high) << 32) | low;
}

void
ioapic_write_iored(
        struct ioapic *ioapic,
        hwirq_t irq,
        uint64_t value)
{
    size_t irq_offset = irq - ioapic->base_irq;
    uint32_t high = (value >> 32);
    uint32_t low = (value & ((1ULL<<32)-1));

    mmio_writel(ioapic->ioregsel, IOAPIC_REG_IOREDTBL_BASE + (irq_offset * 2));
    mmio_writel(ioapic->iowin, low);

    mmio_writel(ioapic->ioregsel, IOAPIC_REG_IOREDTBL_BASE + (irq_offset * 2) + 1);
    mmio_writel(ioapic->iowin, high);
}

static int
ioapic_device_read_name(
        struct device *device,
        char *buf,
        size_t size)
{
    struct ioapic *ioapic =
        container_of(device, struct ioapic, device);

    snprintk(buf, size, "ioapic-%d", ioapic->id);
    return 0;
}

static struct device_ops
ioapic_device_ops = {
    .read_name = ioapic_device_read_name,
};

static int
ioapic_ack_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    return 0;
}

static int
ioapic_eoi_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    return 0;
}

static int
ioapic_trigger_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    return -EINVAL;
}

static int
ioapic_mask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    struct ioapic *ioapic =
        container_of(dev, struct ioapic, dev);

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored |= 1ULL<<16;
    ioapic_write_iored(ioapic, hwirq, iored);

    return 0;
}

static int
ioapic_unmask_irq(
        struct irq_dev *dev,
        hwirq_t hwirq)
{
    struct ioapic *ioapic =
        container_of(dev, struct ioapic, dev);

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored &= ~(1ULL<<16);
    dprintk("ioapic_unmask_irq: IORED=%p\n", iored);
    ioapic_write_iored(ioapic, hwirq, iored);

    return 0;
}

static struct irq_dev_driver
ioapic_irq_driver = {
    .ack_irq = ioapic_ack_irq,
    .eoi_irq = ioapic_eoi_irq,
    .mask_irq = ioapic_mask_irq,
    .unmask_irq = ioapic_unmask_irq,
    .trigger_irq = ioapic_trigger_irq,
};

int
x64_register_ioapic(
        ioapic_id_t id,
        paddr_t reg_base,
        hwirq_t irq_base)
{
    int res;

    struct ioapic *ioapic = kmalloc(sizeof(struct ioapic));
    if(ioapic == NULL) {
        return -ENOMEM;
    }
    memset(ioapic, 0, sizeof(struct ioapic));

    ioapic->id = id;
    ioapic->phys_regs_base = reg_base;
    ioapic->base_irq = irq_base;

    ioapic->regs = mmio_map(ioapic->phys_regs_base, IOAPIC_MMIO_SIZE);
    if(ioapic->regs == NULL) {
        kfree(ioapic);
        return -ENOMEM;
    }

    ioapic->ioregsel = (uint32_t __mmio *)(ioapic->regs + IOAPIC_IOREGSEL_OFFSET);
    ioapic->iowin = (uint32_t __mmio *)(ioapic->regs + IOAPIC_IOWIN_OFFSET);

    uint32_t ver = ioapic_read_reg(
            ioapic, IOAPIC_REG_IOAPICVER);

    ioapic->num_irq = ((ver >> 16) & 0xFF) + 1;
    printk("IOAPIC %ld: irq_base = 0x%x, num_irq = 0x%x\n",
            ioapic->id,
            ioapic->base_irq,
            ioapic->num_irq);

    res = register_device(
            &ioapic->device,
            &ioapic_device_ops,
            NULL);
    if(res) {
        eprintk("Failed to register IOAPIC device (err=%s)\n",
                errnostr(res));
        mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
        kfree(ioapic);
        return res;
    }

    ioapic->dev.device = &ioapic->device;
    ioapic->dev.driver = &ioapic_irq_driver;

    ioapic->irq_domain =
        alloc_irq_domain_linear(
                ioapic->base_irq,
                ioapic->num_irq);

    if(ioapic->irq_domain == NULL) {
        eprintk("x64_register_ioapic: failed to create irq_domain!\n");
        mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
        kfree(ioapic);
        return -EINVAL;
    }

    cpu_id_t next_to_assign = 0;

    for(size_t i = 0; i < ioapic->num_irq; i++) {
        hwirq_t hwirq = ioapic->base_irq + i;
        irq_t irq = irq_domain_revmap(ioapic->irq_domain, hwirq); 
        struct irq_desc *desc;
        if(irq != NULL_IRQ) {
            desc = irq_to_desc(irq);
        } else {
            desc = NULL;
        }

        if(desc == NULL) {
            eprintk("x64_register_ioapic: failed to get irq desc for IO/APIC IRQ 0x%x!\n", hwirq);
            free_irq_domain_linear(ioapic->irq_domain);
            mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
            kfree(ioapic);
            return -EINVAL;
        }

        desc->dev = &ioapic->dev;

        cpu_id_t original_attempted_cpu = next_to_assign;
        apic_id_t apic_id = apic_id_from_cpu(cpu_from_id(next_to_assign));
        if(apic_id >= 16) {
            next_to_assign++;
            if(next_to_assign >= total_num_cpus()) {
                next_to_assign = 0;
            }
            /* 
             * If we trip this assertion, then
             * literally no CPU in the system has an APIC ID less
             * than 16, in which case things are reeeeeally messed up,
             * and there's nothing we can do.
             */
            DEBUG_ASSERT(next_to_assign != original_attempted_cpu);
        }

        irq_t vector_irq = x64_request_cpu_irq_vector(next_to_assign);
        if(vector_irq == NULL_IRQ) {
            eprintk("x64_register_ioapic: failed to get vector for IO/APIC IRQ 0x%x on CPU %ld!\n",
                    hwirq, next_to_assign);
            free_irq_domain_linear(ioapic->irq_domain);
            mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
            kfree(ioapic);
            return -EINVAL;
        }

        struct irq_desc *vector_desc = irq_to_desc(vector_irq);
        if(vector_desc == NULL) {
            eprintk("x64_register_ioapic: failed to get vector descriptor (IRQ=0x%x) for IO/APIC IRQ 0x%x on CPU %ld!\n",
                    vector_irq, hwirq, (sl_t)next_to_assign);
            free_irq_domain_linear(ioapic->irq_domain);
            mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
            kfree(ioapic);
            return -EINVAL;
        }

        hwirq_t vector = vector_desc->hwirq;
        DEBUG_ASSERT(vector <= 0xFF);

        uint64_t iored = ioapic_read_iored(ioapic, hwirq);

        iored &= ~(0xFF); // Set the vector
        iored |= (uint8_t)vector;

        iored &= ~((0b111ULL) << 8); // Fixed Delivery Mode
        iored &= ~(1ULL<<11); // Physical Destination Mode
        iored &= ~(1ULL<<13); // Active High
        iored &= ~(1ULL<<15); // Edge Sensitive
        iored |=  (1ULL<<16); // Masked

        iored &= ~(0xFFULL<<56); // Set the physical APIC ID
        iored |= (uint64_t)(0xF & apic_id) << 56;

        dprintk("IOAPIC IORED = %p\n", iored);

        ioapic_write_iored(ioapic, hwirq, iored);

        struct irq_action *link =
            irq_install_direct_link(vector_desc, desc);
        if(link == NULL) {
            eprintk("x64_register_ioapic: failed to install direct link from vector descriptor (IRQ=0x%x) to IO/APIC IRQ 0x%x on CPU %ld!\n",
                    vector_irq, hwirq, (sl_t)next_to_assign);
            free_irq_domain_linear(ioapic->irq_domain);
            mmio_unmap(ioapic->regs, IOAPIC_MMIO_SIZE);
            kfree(ioapic);
            return -EINVAL;
        }

        printk("Mapped I/OAPIC IRQ %ld to CPU %ld Vector IRQ 0x%x\n",
                hwirq, next_to_assign, vector_desc->hwirq);

        // Get the next CPU to assign an interrupt to
        next_to_assign++;
        if(next_to_assign >= total_num_cpus()) {
            next_to_assign = 0;
        }
    }

    spin_lock(&ioapic_list_lock);
    ilist_push_tail(&ioapic_list, &ioapic->list_node);
    spin_unlock(&ioapic_list_lock);

    return 0;
}

static inline struct ioapic *
x64_get_ioapic(hwirq_t hwirq) 
{
    struct ioapic *ret_ioapic = NULL;

    ilist_node_t *node;
    int irq_state = spin_lock_irq_save(&ioapic_list_lock);
    ilist_for_each(node, &ioapic_list)
    {
        struct ioapic *ioapic =
            container_of(node, struct ioapic, list_node);
        if((ioapic->base_irq < hwirq) &&
          ((ioapic->base_irq + ioapic->num_irq) > hwirq))
        {
            ret_ioapic = ioapic;
            break;
        }
    }
    spin_unlock_irq_restore(&ioapic_list_lock, irq_state);
    return ret_ioapic;
}

irq_t
x64_ioapic_irq(hwirq_t hwirq)
{
    struct ioapic *ioapic = x64_get_ioapic(hwirq);
    if(ioapic == NULL || ioapic->irq_domain == NULL) {
        return NULL_IRQ;
    }
    return irq_domain_revmap(ioapic->irq_domain, hwirq);
}

int
x64_ioapic_set_level_sensitive(hwirq_t hwirq)
{
    struct ioapic *ioapic = x64_get_ioapic(hwirq);
    if(ioapic == NULL) {
        return -EINVAL;
    }

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored |= (1ULL<<15);
    ioapic_write_iored(ioapic, hwirq, iored);
    return 0;
}
int
x64_ioapic_set_edge_triggered(hwirq_t hwirq)
{
    struct ioapic *ioapic = x64_get_ioapic(hwirq);
    if(ioapic == NULL) {
        return -EINVAL;
    }

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored &= ~(1ULL<<15);
    ioapic_write_iored(ioapic, hwirq, iored);
    return 0;
}

int
x64_ioapic_set_active_high(hwirq_t hwirq)
{
    struct ioapic *ioapic = x64_get_ioapic(hwirq);
    if(ioapic == NULL) {
        return -EINVAL;
    }

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored &= ~(1ULL<<13);
    ioapic_write_iored(ioapic, hwirq, iored);
    return 0;
}
int
x64_ioapic_set_active_low(hwirq_t hwirq)
{
    struct ioapic *ioapic = x64_get_ioapic(hwirq);
    if(ioapic == NULL) {
        return -EINVAL;
    }

    uint64_t iored = ioapic_read_iored(ioapic, hwirq);
    iored |= (1ULL<<13);
    ioapic_write_iored(ioapic, hwirq, iored);
    return 0;
}

