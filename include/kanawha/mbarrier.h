#ifndef __KANAWHA__MBARRIER_H__
#define __KANAWHA__MBARRIER_H__

#ifdef CONFIG_X64
#include <arch/x64/mbarrier.h>
#else
#error "Architecture did not define mbarrier.h"
#endif

#ifndef mbarrier
#error "Architecture did not define mbarrier!"
#endif

#endif
