#ifndef __KANAWHA__ARM64_MBARRIER_H__
#define __KANAWHA__ARM64_MBARRIER_H__

static inline void
arm64_isb(void)
{
    asm volatile("isb;" ::: "memory");
}

#define mbarrier mbarrier
static inline void
mbarrier(void)
{
    asm volatile("dsb sy; isb;" ::: "memory");
}

#endif
