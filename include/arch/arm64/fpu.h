#ifndef __KANAWHA__ARM64__FPU_H__
#define __KANAWHA__ARM64__FPU_H__

#include <arch/arm64/sysreg.h>

static inline void
arm64_init_current_fpu(void)
{
    uint64_t cpacr = arm64_sysreg_readq(CPACR_EL1);
    cpacr |= (0b11 << 20); // FPEN = 0b11 (EL0 and EL1 can access)
    cpacr |= (0b11 << 16); // ZEN  = 0b11 (EL0 and EL1 can access)
    arm64_sysreg_writeq(CPACR_EL1, cpacr);
}

#endif
