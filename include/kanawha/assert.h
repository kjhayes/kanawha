#ifndef __KANAWHA__ASSERT_H__
#define __KANAWHA__ASSERT_H__

#include <kanawha/printk.h>
#include <kanawha/types.h>

#ifdef CONFIG_DEBUG_ASSERTIONS

#ifdef CONFIG_X64 
#include <arch/x64/assert.h>
#else
#endif

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


// The architecture can define a more strict or lax version
// of this check if needed
//
// At minimum, this needs to always return 0 if ptr==NULL

#ifdef CONFIG_DEBUG_HIGHER_HALF_KERNEL_ADDRESSES
#define KERNEL_ADDR_HIGHER_HALF_CHECK(ptr) ((((uintptr_t)ptr & (0xF000000000000000ULL)) == (0xF000000000000000ULL)))
#else
#define KERNEL_ADDR_HIGHER_HALF_CHECK(ptr) 1
#endif

#ifndef KERNEL_ADDR 
#define KERNEL_ADDR(ptr) (\
           ((uintptr_t)ptr != 0) && \
           KERNEL_ADDR_HIGHER_HALF_CHECK(ptr) && \
           1)
#endif

#endif
