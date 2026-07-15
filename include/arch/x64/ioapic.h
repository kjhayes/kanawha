#ifndef __KANAWHA__X64_IOAPIC_H__
#define __KANAWHA__X64_IOAPIC_H__

#include <kanawha/dev/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/list.h>
#include <kanawha/mmio.h>
#include <kanawha/vmem.h>

typedef uint8_t ioapic_id_t;

#define IOAPIC_REG_IOAPICID 0
#define IOAPIC_REG_IOAPICVER 1
#define IOAPIC_REG_IOAPICARB 2

#define IOAPIC_REG_IOREDTBL_BASE 0x10

struct ioapic
{
    ioapic_id_t id;
    void __phys *phys_regs_base;

    struct irq_dev dev;

    void __mmio *regs;
    uint32_t __mmio *ioregsel;
    uint32_t __mmio *iowin;

    hwirq_t base_irq;
    size_t num_irq;

    struct irq_domain *irq_domain;

    ilist_node_t list_node;
};

int
x64_register_ioapic(ioapic_id_t id, void __phys *reg_base, hwirq_t irq_base);

// IRQ Lookup
irq_t
x64_ioapic_irq(hwirq_t hwirq);

int
x64_ioapic_set_level_sensitive(hwirq_t hwirq);
int
x64_ioapic_set_edge_triggered(hwirq_t hwirq);

int
x64_ioapic_set_active_high(hwirq_t hwirq);
int
x64_ioapic_set_active_low(hwirq_t hwirq);

#endif
