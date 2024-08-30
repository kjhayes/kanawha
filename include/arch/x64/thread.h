#ifndef __KANAWHA__ARCH_X64_THREAD_H__
#define __KANAWHA__ARCH_X64_THREAD_H__

#include <kanawha/stdint.h>
#include <kanawha/printk.h>

struct arch_thread_state
{
    void *kernel_stack_top; // Stack grows down so this is actually the lowest address
    size_t kernel_stack_size;
    uint64_t kernel_rsp;
};

#endif
