#ifndef __KANAWHA_ARCH_RISCV64__PERCPU_H__
#define __KANAWHA_ARCH_RISCV64__PERCPU_H__

#include <kanawha/types.h>
#include <kanawha/cpu.h>

#define __arch_percpu_ptr(ptr) \
    ({\
     NULL;\
     })

#define __arch_percpu_ptr_specific(ptr, cpu_id) \
    ({\
     NULL;\
     })

#endif
