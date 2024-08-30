
#include <kanawha/common.h>
#include <kanawha/export.h>

void arch_halt(void) {
    asm volatile ("hlt");
}

EXPORT_SYMBOL(arch_halt);

