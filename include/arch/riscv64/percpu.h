#ifndef __KANAWHA_ARCH_RISCV64__PERCPU_H__
#define __KANAWHA_ARCH_RISCV64__PERCPU_H__

#include <kanawha/types.h>
#include <kanawha/cpu.h>

struct riscv64_percpu_state {
    size_t percpu_offset;
} __attribute__((packed));

extern struct riscv64_percpu_state
__riscv64_percpu_data[CONFIG_MAX_CPUS];

#define __arch_percpu_ptr(ptr) \
    ({\
     struct riscv64_percpu_state *state;\
     asm volatile ("mv %0, tp" : "=r" (state));\
     (typeof(ptr)*)(((void*)ptr) + state->percpu_offset);\
     })

#define __arch_percpu_ptr_specific(ptr, cpu_id) \
    ({\
     void *ptr_spec = (typeof(ptr)*)(\
             ((void*)ptr) + \
             __riscv64_percpu_data[cpu_id].percpu_offset\
             );\
     ptr_spec;\
     })

#endif
