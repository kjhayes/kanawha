#ifndef __KANAWHA_ARCH_RISCV64__VMEM_H__
#define __KANAWHA_ARCH_RISCV64__VMEM_H__

#include <kanawha/pointer.h>
#include <kanawha/printk.h>

#define VMEM_MIN_PAGE_ORDER 12

struct vmem_map;

struct arch_vmem_map
{
    int root_level;
    struct riscv64_sv_page_table __phys *root_table;
};

struct arch_vmem_region
{
    int root_level;
    struct riscv64_sv_page_table __phys *root_table;
};

extern size_t __riscv64_identity_map_offset; // Assume low mem is identity mapped at boot
                                                 // (TODO This is not really a safe assumption)

static inline void *
__va(void __phys * paddr) {
    return (void*)paddr + __riscv64_identity_map_offset;
}

static inline void __phys *
__pa(void * vaddr) {
    return (void __phys *)(vaddr - __riscv64_identity_map_offset);
}

// Returns 0 if not-present 1 if present, -ERRNO on error
int
riscv64_vmem_map_page_is_present(
        struct vmem_map *map,
        void *vaddr);

#endif
