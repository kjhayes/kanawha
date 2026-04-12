
#include <kanawha/paging/paging.h>
#include <kanawha/irq.h>
#include <kanawha/vmem.h>
#include <arch/x64/sysreg.h>
#include <arch/x64/mmu.h>

#define NUM_LEVELS 4

const static order_t
x64_level_num_entries_order[NUM_LEVELS] = {
    9, 9, 9, 9,
};

const static order_t
x64_level_entry_order[NUM_LEVELS] = {
    3, 3, 3, 3,
};

const static order_t
x64_level_entry_region_order[NUM_LEVELS] = {
    12,
    21,
    30,
    39,
};

const static unsigned long
x64_level_flags[NUM_LEVELS] = {
    // PT
    0
    |PAGING_LEVEL_FLAG_CAN_BE_LEAF
    ,
    // PD
    0
#ifdef CONFIG_X64_ASSUME_2MB_PAGES
    |PAGING_LEVEL_FLAG_CAN_BE_LEAF
#endif
    ,
    // PDPT
    0
#ifdef CONFIG_X64_ASSUME_1GB_PAGES
    |PAGING_LEVEL_FLAG_CAN_BE_LEAF
#endif
    ,
    // PML4
    0
    ,
};

static size_t
x64_paging_level_addr_table_index(
        int level,
        void *addr)
{
    switch(level)
    {
    case 0:
        return X64_PT_INDEX_OF_ADDR((uintptr_t)addr);
    case 1:
        return X64_PD_INDEX_OF_ADDR((uintptr_t)addr);
    case 2:
        return X64_PDPT_INDEX_OF_ADDR((uintptr_t)addr);
    case 3:
        return X64_PML4_INDEX_OF_ADDR((uintptr_t)addr);
    case 4:
        return X64_PML5_INDEX_OF_ADDR((uintptr_t)addr);
    default:
        return -EINVAL;
    }
    return 0;
}

static int
x64_paging_get_entry_flags(
        int level,
        void *entry_data,
        unsigned long *flags_out)
{
    unsigned long flags = 0;

    // Every entry on x64 is readable and kernel accessible
    flags |= PAGING_ENTRY_READABLE;
    flags |= PAGING_ENTRY_KERNEL_ACCESS;

    uint64_t entry = *(uint64_t*)entry_data;

    int is_leaf;
    switch(level)
    {
    case 0:
        is_leaf = 1;
        break;
    case 1:
        is_leaf = !!(entry & X64_PD_ENTRY_PAGE_SIZE);
        break;
    case 2:
        is_leaf = !!(entry & X64_PDPT_ENTRY_PAGE_SIZE);
        break;
    default:
        is_leaf = 0;
        break;
    }

    if(is_leaf) {
        flags |= PAGING_ENTRY_IS_LEAF;
    } else {
        flags |= PAGING_ENTRY_IS_TABLE;
    }

    switch(level) {
        case 0:
            flags |= entry & X64_PT_LEAF_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PT_LEAF_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PT_LEAF_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PT_LEAF_CACHE_DISABLE ? PAGING_ENTRY_CACHE_DISABLE : 0;
            break;
        case 1:
            if(is_leaf) {
            flags |= entry & X64_PD_LEAF_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PD_LEAF_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PD_LEAF_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PD_LEAF_CACHE_DISABLE ? PAGING_ENTRY_CACHE_DISABLE : 0;
            } else {
            flags |= entry & X64_PD_ENTRY_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PD_ENTRY_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PD_ENTRY_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PD_ENTRY_VMEM_SHARED_MAP ? PAGING_ENTRY_SHARED : 0;
            }
            break;
        case 2:
            if(is_leaf) {
            flags |= entry & X64_PDPT_LEAF_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PDPT_LEAF_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PDPT_LEAF_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PDPT_LEAF_CACHE_DISABLE ? PAGING_ENTRY_CACHE_DISABLE : 0;
            } else {
            flags |= entry & X64_PDPT_ENTRY_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PDPT_ENTRY_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PDPT_ENTRY_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PDPT_ENTRY_VMEM_SHARED_MAP ? PAGING_ENTRY_SHARED : 0;
            }
            break;
        case 3:
            flags |= entry & X64_PML4_ENTRY_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PML4_ENTRY_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PML4_ENTRY_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PML4_ENTRY_VMEM_SHARED_MAP ? PAGING_ENTRY_SHARED : 0;
            break;
        case 4:
            flags |= entry & X64_PML5_ENTRY_PRESENT ? PAGING_ENTRY_PRESENT : 0;
            flags |= entry & X64_PML5_ENTRY_WRITE ? PAGING_ENTRY_WRITEABLE : 0;
            flags |= entry & X64_PML5_ENTRY_USER ? PAGING_ENTRY_USER_ACCESS : 0;
            flags |= entry & X64_PML5_ENTRY_VMEM_SHARED_MAP ? PAGING_ENTRY_SHARED : 0;
            break;
        default:
            return -EINVAL;
    }

    *flags_out = flags;

    return 0;
}

static inline int
x64_paging_modify_entry_flags(
        int level,
        void *entry_data,
        unsigned long flags,
        int clear)
{
    if(clear && (flags & PAGING_ENTRY_READABLE)) {
        wprintk("x64_paging_modify_entry_flags: cannot mark entry as non-readable (ignoring)!\n");
    }
    if(clear && (flags & PAGING_ENTRY_KERNEL_ACCESS)) {
        wprintk("x64_paging_modify_entry_flags: cannot mark entry as non-kernel accessible (ignoring)!\n");
    }

#ifdef CONFIG_DEBUGGING
    // Complicated validation, only do it
    // if debugging is on (otherwise we will
    // do this a *lot* for no real reason)
    unsigned long disallowed_set = 0;
    unsigned long disallowed_clear = 0;
    switch(level) {
        case 0:
            disallowed_set = 0
                |PAGING_ENTRY_IS_TABLE
                |PAGING_ENTRY_SHARED
                ;
            disallowed_clear = 0
                |PAGING_ENTRY_IS_LEAF
                ;
            break;
        case 1:
            break;
        case 2:
            break;
        case 3:
            disallowed_set = 0
                |PAGING_ENTRY_IS_LEAF
                ;
            disallowed_clear = 0
                |PAGING_ENTRY_IS_TABLE
                ;
            break;
        case 4:
            disallowed_set = 0
                |PAGING_ENTRY_IS_LEAF
                ;
            disallowed_clear = 0
                |PAGING_ENTRY_IS_TABLE
                ;
            break;
    }

    if(clear) {
        if(flags & disallowed_clear) {
            return -EINVAL;
        }
    } else {
        if(flags & disallowed_set) {
            return -EINVAL;
        }
    }
#endif

    unsigned long mask = 0;

    int is_leaf = flags & PAGING_ENTRY_IS_LEAF;

    switch(level) {
        case 0:
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PT_LEAF_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PT_LEAF_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PT_LEAF_USER : 0;
            mask |= PAGING_ENTRY_CACHE_DISABLE & flags ? X64_PT_LEAF_CACHE_DISABLE : 0;
            break;
        case 1:
            if(is_leaf) {
            mask |= X64_PD_LEAF_PAGE_SIZE;
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PD_LEAF_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PD_LEAF_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PD_LEAF_USER : 0;
            mask |= PAGING_ENTRY_CACHE_DISABLE & flags ? X64_PD_LEAF_CACHE_DISABLE : 0;
            } else {
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PD_ENTRY_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PD_ENTRY_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PD_ENTRY_USER : 0;
            mask |= PAGING_ENTRY_SHARED & flags ? X64_PD_ENTRY_VMEM_SHARED_MAP : 0;
            }
            break;
        case 2:
            if(is_leaf) {
            mask |= X64_PDPT_LEAF_PAGE_SIZE;
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PDPT_LEAF_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PDPT_LEAF_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PDPT_LEAF_USER : 0;
            mask |= PAGING_ENTRY_CACHE_DISABLE & flags ? X64_PDPT_LEAF_CACHE_DISABLE : 0;
            } else {
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PDPT_ENTRY_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PDPT_ENTRY_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PDPT_ENTRY_USER : 0;
            mask |= PAGING_ENTRY_SHARED & flags ? X64_PDPT_ENTRY_VMEM_SHARED_MAP : 0;
            }
            break;
        case 3:
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PML4_ENTRY_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PML4_ENTRY_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PML4_ENTRY_USER : 0;
            mask |= PAGING_ENTRY_SHARED & flags ? X64_PML4_ENTRY_VMEM_SHARED_MAP : 0;
            break;
        case 4:
            mask |= PAGING_ENTRY_PRESENT & flags ? X64_PML5_ENTRY_PRESENT : 0;
            mask |= PAGING_ENTRY_WRITEABLE & flags ? X64_PML5_ENTRY_WRITE : 0;
            mask |= PAGING_ENTRY_USER_ACCESS & flags ? X64_PML5_ENTRY_USER : 0;
            mask |= PAGING_ENTRY_SHARED & flags ? X64_PML5_ENTRY_VMEM_SHARED_MAP : 0;
            break;
    }

    uint64_t *entry_ptr = entry_data;
    if(clear) {
        *entry_ptr &= ~mask;
    } else {
        *entry_ptr |= mask;
    }
    return 0;
}

static int
x64_paging_set_entry_flags(
        int level,
        void *entry_data,
        unsigned long flags)
{
    return x64_paging_modify_entry_flags(
            level,
            entry_data,
            flags,
            0);
}

static int
x64_paging_clear_entry_flags(
        int level,
        void *entry_data,
        unsigned long flags)
{
    return x64_paging_modify_entry_flags(
            level,
            entry_data,
            flags,
            1);
}

static int
x64_paging_entry_clear(
        int level,
        void *entry_data)
{
    *(uint64_t*)entry_data = 0;
    return 0;
}

static inline uint64_t
x64_addr_mask(int level)
{
    switch(level)
    {
    case 0:
        return X64_PT_LEAF_ADDR_MASK;
    case 1:
        return X64_PD_ENTRY_ADDR_MASK;
    case 2:
        return X64_PDPT_ENTRY_ADDR_MASK;
    case 3:
        return X64_PML4_ENTRY_ADDR_MASK;
    case 4:
        return X64_PML5_ENTRY_ADDR_MASK;
    default:
        panic("pt_level_addr_mask: invalid pt_level (%d)\n", level);
    }
}

static int
x64_paging_read_entry_addr(
        int level,
        void *entry_data,
        void __phys **addr)
{
    uint64_t mask = x64_addr_mask(level);
    uint64_t entry = *(uint64_t*)entry_data;
    *addr = (void __phys *)(entry & mask);
    return 0;
}

static int
x64_paging_write_entry_addr(
        int level,
        void *entry_data,
        void __phys *addr)
{
    uint64_t mask = x64_addr_mask(level);
    uint64_t *entry = (uint64_t*)entry_data;
    *entry &= ~mask;
    *entry |= (mask & (uint64_t)addr);
    return 0;
}

static struct paging_mode
x64_paging_mode = {
    .num_levels = NUM_LEVELS,
    .level_num_entries_order = x64_level_num_entries_order,
    .level_entry_order = x64_level_entry_order,
    .level_entry_region_order = x64_level_entry_region_order,
    .level_flags = x64_level_flags,

    .level_addr_table_index = x64_paging_level_addr_table_index,
    .get_entry_flags = x64_paging_get_entry_flags,
    .set_entry_flags = x64_paging_set_entry_flags,
    .clear_entry_flags = x64_paging_clear_entry_flags,
    .clear_entry = x64_paging_entry_clear,
    .read_entry_addr = x64_paging_read_entry_addr,
    .write_entry_addr = x64_paging_write_entry_addr,
};

const struct paging_mode *
arch_paging_mode(void)
{
    return &x64_paging_mode;
}

#ifdef CONFIG_VMEM_VIA_PAGING

struct vmem_map_paging_state *
arch_get_vmem_map_paging_state(
        struct vmem_map *map)
{
    return &map->arch_state.paging_state;
}

struct vmem_region_paging_state *
arch_get_vmem_region_paging_state(
        struct vmem_region *region)
{
    return &region->arch_state.paging_state;
}

int
arch_paging_set_pt_root(
        void __phys *pt_root)
{
    uint64_t cr3 = (uint64_t)pt_root;
    write_cr3(cr3);
    return 0;
}

int
arch_paging_flush_tlb(
        void __phys *cond_pt_root,
        int force)
{
    int irq_flags = disable_save_irqs();
    uint64_t cr3 = read_cr3();
    if((cr3 == (uint64_t)cond_pt_root) || force)
    {
        write_cr3(cr3);
    }
    enable_restore_irqs(irq_flags);
    return 0;
}

#endif

