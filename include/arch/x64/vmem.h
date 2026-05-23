#ifndef __KANAWHA__ARCH_X64_VIRT_MEM_H__
#define __KANAWHA__ARCH_X64_VIRT_MEM_H__

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
#else
    void __phys *pt_root;
    int pt_level;
#endif
};

struct arch_vmem_region
{
#ifdef CONFIG_VMEM_VIA_PAGING
    struct vmem_region_paging_state paging_state;
#else
    void __phys *pt_table;
    int pt_level;

    uint64_t pt_entry;
    int entry_only;

    int paged_max_entry_level;
#endif
};

#endif
