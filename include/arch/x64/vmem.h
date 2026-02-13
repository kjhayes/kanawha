#ifndef __KANAWHA__ARCH_X64_VIRT_MEM_H__
#define __KANAWHA__ARCH_X64_VIRT_MEM_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/assert.h>

#define VMEM_MIN_PAGE_ORDER 12

struct arch_vmem_map 
{
    void __phys * pt_root;
    int pt_level;
};

struct arch_vmem_region 
{
    void __phys * pt_table;
    int pt_level;

    uint64_t pt_entry;
    int entry_only;

    int paged_max_entry_level;
};

static inline void *
__va(void __phys * paddr)
{
    DEBUG_ASSERT((uintptr_t)paddr < (uintptr_t)1ULL<<CONFIG_X64_IDENTITY_MAP_ORDER);
    return (void *)(paddr + CONFIG_X64_VIRTUAL_BASE);
}

static inline void __phys *
__pa(void * vaddr)
{
    void __phys *paddr = (void __phys *)(vaddr - CONFIG_X64_VIRTUAL_BASE);
    DEBUG_ASSERT((uintptr_t)paddr < (uintptr_t)1ULL<<CONFIG_X64_IDENTITY_MAP_ORDER);
    return paddr;
}

#endif
