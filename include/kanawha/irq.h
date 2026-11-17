#ifndef __KANAWHA__IRQ_H__
#define __KANAWHA__IRQ_H__

#include <kanawha/common.h>
#include <kanawha/types.h>

#define NULL_IRQ ((irq_t)(-1))
typedef uint32_t irq_t;
typedef uint32_t hwirq_t;

#define IRQ_MAX (~(uint32_t)0)

int
arch_irq_disable(void);
int
arch_irq_enable(void);
int
arch_irqs_enabled(void);

static inline int
disable_irqs(void)
{
    return arch_irq_disable();
}

static inline int
enable_irqs(void)
{
    return arch_irq_enable();
}

static inline int
irqs_enabled(void)
{
    return arch_irqs_enabled();
}

static inline int
disable_save_irqs(void)
{
    int state = irqs_enabled();
    if(state)
    {
        disable_irqs();
    }
    return state;
}

static inline void
enable_restore_irqs(int state)
{
    if(state)
    {
        enable_irqs();
    }
}

// Called by the architecture when an interrupt goes unhandled

#endif
