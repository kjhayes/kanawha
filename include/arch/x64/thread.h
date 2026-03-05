#ifndef __KANAWHA__ARCH_X64_THREAD_H__
#define __KANAWHA__ARCH_X64_THREAD_H__

#include <kanawha/printk.h>
#include <kanawha/stack.h>
#include <kanawha/types.h>

#define X64_XSAVE_BUFLEN 512

struct arch_thread_state
{
    struct thread_stack stack;

    uint64_t fsbase;

    __attribute__((aligned(16))) uint8_t xsave_buffer[X64_XSAVE_BUFLEN];
};

#endif
