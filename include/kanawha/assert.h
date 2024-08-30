#ifndef __KANAWHA__ASSERT_H__
#define __KANAWHA__ASSERT_H__

#include <kanawha/printk.h>
#include <kanawha/stdint.h>

#ifdef CONFIG_DEBUG_ASSERTIONS

#define DEBUG_ASSERT(__COND)\
    do {\
    if(!(__COND)) {\
        panic("Failed Assertion \"" #__COND "\" (%s:%ld)\n", __FILE__, (sl_t)__LINE__);\
    }\
    } while (0)

#define DEBUG_ASSERT_MSG(__COND, __FMT, ...)\
    do {\
    if(!(__COND)) {\
        panic("Failed Assertion: \"" #__COND "\" (%s:%ld) " __FMT, __FILE__, (sl_t)__LINE__, ##__VA_ARGS__);\
    }\
    } while(0)

#else
#define DEBUG_ASSERT(...)
#define DEBUG_ASSERT_MSG(...)
#endif

#endif
