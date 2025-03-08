#ifndef __KANAWHA__ARCH_X64_THREAD_H__
#define __KANAWHA__ARCH_X64_THREAD_H__

#include <kanawha/types.h>
#include <kanawha/printk.h>
#include <kanawha/stack.h>

struct arch_thread_state
{
    struct thread_stack stack;
};

#endif
