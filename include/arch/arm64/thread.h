#ifndef __KANAWHA__ARM64_THREAD_H__
#define __KANAWHA__ARM64_THREAD_H__

#include <kanawha/stack.h>

struct arch_thread_state
{
    struct thread_stack stack;
};

#endif
