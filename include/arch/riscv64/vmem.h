#ifndef __KANAWHA_ARCH_RISCV64__VMEM_H__
#define __KANAWHA_ARCH_RISCV64__VMEM_H__

#include <kanawha/pointer.h>
#include <kanawha/printk.h>

#define VMEM_MIN_PAGE_ORDER 12

struct arch_vmem_map {

};

struct arch_vmem_region {

};

static inline void *
__va(void __phys * paddr) {
    panic("__va is unimplemented!\n");
}

static inline void __phys *
__pa(void * vaddr) {
    panic("__pa is unimplemented!\n");
}

#endif
