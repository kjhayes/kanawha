#ifndef __KANAWHA_ARCH_RISCV64__THREAD_H__
#define __KANAWHA_ARCH_RISCV64__THREAD_H__

#include <kanawha/stack.h>

struct arch_thread_state {
    struct thread_stack stack;
};

#endif
