#ifndef __KANAWHA__ARCH_X64_MBARRIER_H__
#define __KANAWHA__ARCH_X64_MBARRIER_H__

#define mbarrier mbarrier
static inline void
mbarrier(void)
{
    asm volatile("sfence" ::: "memory");
}

#endif
