#ifndef __KANAWHA__X64_STACK_H__
#define __KANAWHA__X64_STACK_H__

#include <kanawha/stdint.h>
#include <kanawha/vmem.h>

struct x64_thread_stack
{
    struct vmem_region *region;
    uintptr_t virt_base;
    order_t virt_order;

    order_t order;
    paddr_t page;

    uintptr_t rsp;

    uintptr_t stack_base; // highest address
    uintptr_t stack_top; // lowest address
};

int
x64_thread_stack_init(
        struct thread_state *thread,
        order_t order);

int
x64_thread_stack_deinit(
        struct thread_state *thread);

#endif
