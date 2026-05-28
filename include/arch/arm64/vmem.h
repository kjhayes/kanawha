#ifndef __KANAWHA__ARM64_VMEM_H__
#define __KANAWHA__ARM64_VMEM_H__

#include <kanawha/assert.h>
#include <kanawha/pointer.h>
#include <kanawha/types.h>

#ifdef CONFIG_VMEM_VIA_PAGING
#include <kanawha/paging/vmem.h>
#endif

#define VMEM_MIN_PAGE_ORDER 12

struct arch_vmem_map
{
#ifdef CONFIG_VMEM_VIA_PAGING
    struct vmem_map_paging_state paging_state;
#endif
};

struct arch_vmem_region
{
#ifdef CONFIG_VMEM_VIA_PAGING
    struct vmem_region_paging_state paging_state;
#endif
};

static inline void *
__va(void __phys *paddr)
{
    panic("__va called!\n");
    return NULL;
}

static inline void __phys *
__pa(void *vaddr)
{
    panic("__pa called!\n");
    return NULL;
}

#endif
