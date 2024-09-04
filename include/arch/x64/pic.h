#ifndef __KANAWHA__ARCH_X64_PIC_H__
#define __KANAWHA__ARCH_X64_PIC_H__

#include <kanawha/irq_domain.h>

/*
 * Kanawha cannot really run with the 8259 enabled,
 * but we still provide an IRQ domain for the PIC so that
 * devices such as a PS/2 keyboard can still attach to them.
 *
 * (The IOAPIC/MADT handling code should link this domain to
 *  IOAPIC IRQ lines appropriately)
 */

struct irq_domain *
x64_pic_irq_domain(void);

static inline irq_t
x64_pic_irq(hwirq_t hwirq)
{
    struct irq_domain *domain =
        x64_pic_irq_domain();
    if(domain == NULL) {
        return NULL_IRQ;
    }
    return irq_domain_revmap(domain, hwirq);
}

#endif
