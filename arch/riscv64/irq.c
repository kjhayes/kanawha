
#include <kanawha/irq.h>

int arch_irq_disable(void)
{
    panic("arch_irq_disable is unimplemented!\n");
    return -EUNIMPL;
}

int arch_irq_enable(void)
{
    panic("arch_irq_enable is unimplemented!\n");
    return -EUNIMPL;
}

int arch_irqs_enabled(void)
{
    panic("arch_irqs_enabled is unimplemented!\n");
    return -EUNIMPL;
}

