#ifndef __KANAWHA__ARCH_RISCV64_MBARRIER_H__
#define __KANAWHA__ARCH_RISCV64_MBARRIER_H__

#define mbarrier mbarrier
static inline void
mbarrier(void)
{
    asm volatile("fence" ::: "memory");
}

#endif
