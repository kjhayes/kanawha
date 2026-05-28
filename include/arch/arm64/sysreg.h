#ifndef __KANAWHA__ARM64__SYSREG_H__
#define __KANAWHA__ARM64__SYSREG_H__

#include <kanawha/types.h>

#define arm64_sysreg_readq(__name)\
    ({\
     uint64_t value;\
     asm volatile ("msr " #__name ", %0" : "=r"(value));\
     value;\
     })

#define arm64_sysreg_writeq(__name, __value)\
    ({\
     asm volatile ("mrs %0, " #__name :: "r"(__value));\
     })

#endif
