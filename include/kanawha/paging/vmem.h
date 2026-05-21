#ifndef __KANAWHA__PAGING_VMEM_H__
#define __KANAWHA__PAGING_VMEM_H__
#ifdef CONFIG_VMEM_VIA_PAGING

#include <kanawha/paging/paging.h>
#include <kanawha/paging/pagetable.h>

struct vmem_map;
struct vmem_region;

struct vmem_region_paging_state
{
    int entry_only;
    uint8_t pt_entry_buffer[PAGING_PT_ENTRY_BUFLEN];

    int paged_max_entry_level;

    struct pagetable pagetable;
};
struct vmem_map_paging_state
{
    struct pagetable pagetable;
};

struct vmem_map_paging_state *
arch_get_vmem_map_paging_state(struct vmem_map *map);

struct vmem_region_paging_state *
arch_get_vmem_region_paging_state(struct vmem_region *map);

int
arch_paging_set_pt_root(void __phys *pt_root, int root_level);

int
arch_paging_flush_tlb(void __phys *cond_pt_root, int force);

#else
#error "Included paging/vmem.h without CONFIG_VMEM_VIA_PAGING"
#endif /* CONFIG_VMEM_VIA_PAGING */
#endif
