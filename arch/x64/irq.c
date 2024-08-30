
#include <arch/x64/sysreg.h>
#include <kanawha/export.h>

int arch_irq_enable(void) {
    asm volatile ("sti" ::: "memory");
    return 0;
}

int arch_irq_disable(void) {
    asm volatile ("cli" ::: "memory");
    return 0;
}

int arch_irqs_enabled(void) {
    uint64_t rflags = read_rflags();
    return (rflags >> 9) & 0x1;
}

EXPORT_SYMBOL(arch_irq_enable);
EXPORT_SYMBOL(arch_irq_disable);
EXPORT_SYMBOL(arch_irqs_enabled);

