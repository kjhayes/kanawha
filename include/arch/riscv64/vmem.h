#ifndef __KANAWHA_ARCH_RISCV64__VMEM_H__
#define __KANAWHA_ARCH_RISCV64__VMEM_H__

#include <kanawha/pointer.h>
#include <kanawha/printk.h>
#ifndef CONFIG_RISCV64_IMPLEMENT_VMEM_DIRECTLY
#include <kanawha/paging/vmem.h>
#endif 

#define VMEM_MIN_PAGE_ORDER 12

struct vmem_map;

struct arch_vmem_map
{
#ifdef CONFIG_RISCV64_IMPLEMENT_VMEM_DIRECTLY
    int root_level;
    struct riscv64_sv_page_table __phys *root_table;
#else
    struct vmem_map_paging_state paging_state;
#endif
};

struct arch_vmem_region
{
#ifdef CONFIG_RISCV64_IMPLEMENT_VMEM_DIRECTLY
    int root_level;
    struct riscv64_sv_page_table __phys *root_table;
#else
    struct vmem_region_paging_state paging_state;
#endif
};

extern size_t __riscv64_identity_map_offset; // Assume low mem is identity
                                             // mapped at boot (TODO This is
                                             // not really a safe assumption)
extern size_t __riscv64_identity_map_size;

static inline void *
__va(void __phys *paddr)
{
    DEBUG_ASSERT((uintptr_t)paddr < (uintptr_t)__riscv64_identity_map_size);
    return (void *)paddr + __riscv64_identity_map_offset;
}

static inline void __phys *
__pa(void *vaddr)
{
    DEBUG_ASSERT((uintptr_t)vaddr >= (uintptr_t)__riscv64_identity_map_offset);
    void __phys *paddr = (void __phys *)(vaddr - __riscv64_identity_map_offset);
    DEBUG_ASSERT((uintptr_t)paddr < (uintptr_t)__riscv64_identity_map_size);
    return paddr;
}

uint64_t
riscv64_vmem_map_get_satp(
        struct vmem_map *map);

#endif
