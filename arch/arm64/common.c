
#include <kanawha/common.h>
#include <kanawha/export.h>
#include <kanawha/irq.h>

void
arch_halt(void)
{
    asm volatile("wfi");
}

EXPORT_SYMBOL(arch_halt);
