
#include <arch/arm64/mmu.h>
#include <kanawha/irq.h>
#include <kanawha/paging/paging.h>
#include <kanawha/vmem.h>

// We only use up to PML4
#define NUM_LEVELS 4

const static order_t arm64_level_num_entries_order[] = {};
const static order_t arm64_level_entry_order[] = {};
const static order_t arm64_level_entry_region_order[] = {};
const static unsigned long arm64_level_flags[] = {};

static size_t
arm64_paging_level_addr_table_index(int level, void *addr)
{
    return -EUNIMPL;
}

static int
arm64_paging_get_entry_flags(int level,
                           void *entry_data,
                           unsigned long *flags_out)
{
    return -EUNIMPL;
}

static inline int
arm64_paging_modify_entry_flags(int level,
                              void *entry_data,
                              unsigned long flags,
                              int clear)
{
    return -EUNIMPL;
}

static int
arm64_paging_set_entry_flags(int level, void *entry_data, unsigned long flags)
{
    return arm64_paging_modify_entry_flags(level, entry_data, flags, 0);
}

static int
arm64_paging_clear_entry_flags(int level, void *entry_data, unsigned long flags)
{
    return arm64_paging_modify_entry_flags(level, entry_data, flags, 1);
}

static int
arm64_paging_entry_clear(int level, void *entry_data)
{
    *(uint64_t *)entry_data = 0;
    return 0;
}

static int
arm64_paging_read_entry_addr(int level, void *entry_data, void __phys **addr)
{
    return -EUNIMPL;
}

static int
arm64_paging_write_entry_addr(int level, void *entry_data, void __phys *addr)
{
    return -EUNIMPL;
}

static struct paging_mode arm64_paging_mode = {
    .num_levels = NUM_LEVELS,
    .level_num_entries_order = arm64_level_num_entries_order,
    .level_entry_order = arm64_level_entry_order,
    .level_entry_region_order = arm64_level_entry_region_order,
    .level_flags = arm64_level_flags,

    .level_addr_table_index = arm64_paging_level_addr_table_index,
    .get_entry_flags = arm64_paging_get_entry_flags,
    .set_entry_flags = arm64_paging_set_entry_flags,
    .clear_entry_flags = arm64_paging_clear_entry_flags,
    .clear_entry = arm64_paging_entry_clear,
    .read_entry_addr = arm64_paging_read_entry_addr,
    .write_entry_addr = arm64_paging_write_entry_addr,
};

const struct paging_mode *
arch_paging_mode(void)
{
    return &arm64_paging_mode;
}

#ifdef CONFIG_VMEM_VIA_PAGING

struct vmem_map_paging_state *
arch_get_vmem_map_paging_state(struct vmem_map *map)
{
    return &map->arch_state.paging_state;
}

struct vmem_region_paging_state *
arch_get_vmem_region_paging_state(struct vmem_region *region)
{
    return &region->arch_state.paging_state;
}

int
arch_paging_set_pt_root(void __phys *pt_root, int level)
{
    return -EUNIMPL;
}

int
arch_paging_flush_tlb(void __phys *cond_pt_root, int force)
{
    return -EUNIMPL;
}
#endif
