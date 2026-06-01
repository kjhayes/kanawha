
#include <kanawha/export.h>
#include <arch/arm64/sysreg.h>
#include <arch/arm64/mbarrier.h>
#include <kanawha/init.h>

int
arch_irq_enable(void)
{
    asm volatile("msr DAIFClr, 0xF; isb;");
    return 0;
}

int
arch_irq_disable(void)
{
    asm volatile("msr DAIFSet, 0xF; isb;");
    return 0;
}

int
arch_irqs_enabled(void)
{
    uint64_t daif = 0;
    asm volatile("mrs %0, DAIF; isb" : "=r"(daif));
    if(daif) {
        return 0;
    } else {
        return 1;
    }
}

EXPORT_SYMBOL(arch_irq_enable);
EXPORT_SYMBOL(arch_irq_disable);
EXPORT_SYMBOL(arch_irqs_enabled);
