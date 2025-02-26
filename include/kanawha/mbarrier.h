#ifndef __KANAWHA__MBARRIER_H__
#define __KANAWHA__MBARRIER_H__

#if defined(CONFIG_X64)
#include <arch/x64/mbarrier.h>
#elif defined(CONFIG_RISCV64)
#include <arch/riscv64/mbarrier.h>
#else
#error "Architecture did not define mbarrier.h"
#endif

#ifndef mbarrier
#error "Architecture did not define mbarrier!"
#endif

#endif
