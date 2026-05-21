
#include <arch/riscv64/mmu.h>
#include <arch/riscv64/csr.h>
#include <kanawha/irq.h>
#include <kanawha/paging/paging.h>
#include <kanawha/paging/pagetable.h>
#include <kanawha/vmem.h>

#define RISCV64_MAX_NUM_PAGING_LEVELS 5

#ifdef CONFIG_RISCV64_SV57
#define NUM_LEVELS 5
#else
#ifdef CONFIG_RISCV64_SV48
#define NUM_LEVELS 4
#else
#ifdef CONFIG_RISCV64_SV39
#define NUM_LEVELS 3
#else
#error                                                                         \
    "One of CONFIG_RISCV64_SV39, CONFIG_RISCV64_SV48, or CONFIG_RISCV64_SV57 must be defined!"
#endif
#endif
#endif

const static order_t
riscv64_level_num_entries_order[RISCV64_MAX_NUM_PAGING_LEVELS] =
{
    9,
    9,
    9,
    9,
    9,
};

const static order_t
riscv64_level_entry_order[RISCV64_MAX_NUM_PAGING_LEVELS] = {
    RISCV64_SV_ENTRY_DATA_ORDER,
    RISCV64_SV_ENTRY_DATA_ORDER,
    RISCV64_SV_ENTRY_DATA_ORDER,
    RISCV64_SV_ENTRY_DATA_ORDER,
    RISCV64_SV_ENTRY_DATA_ORDER,
};

const static order_t
riscv64_level_entry_region_order[RISCV64_MAX_NUM_PAGING_LEVELS] = {
    RISCV64_SV_PAGE_ORDER_LEVEL_0,
    RISCV64_SV_PAGE_ORDER_LEVEL_1,
    RISCV64_SV_PAGE_ORDER_LEVEL_2,
    RISCV64_SV_PAGE_ORDER_LEVEL_3,
    RISCV64_SV_PAGE_ORDER_LEVEL_4,
};

const static unsigned long
riscv64_level_flags[RISCV64_MAX_NUM_PAGING_LEVELS] = {
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
};

static size_t
riscv64_paging_level_addr_table_index(int level, void *addr)
{
    DEBUG_ASSERT(level < NUM_LEVELS);
    size_t index;
    switch(level)
    {
    case 0:
        index = RISCV64_SV_LEVEL_0_INDEX_OF_ADDR((uintptr_t)addr);
        break;
    case 1:
        index = RISCV64_SV_LEVEL_1_INDEX_OF_ADDR((uintptr_t)addr);
        break;
    case 2:
        index = RISCV64_SV_LEVEL_2_INDEX_OF_ADDR((uintptr_t)addr);
        break;
    case 3:
        index = RISCV64_SV_LEVEL_3_INDEX_OF_ADDR((uintptr_t)addr);
        break;
    case 4:
        index = RISCV64_SV_LEVEL_4_INDEX_OF_ADDR((uintptr_t)addr);
        break;
    default:
        panic("sv_level_index_of_addr was given an invalid level=%d\n", level);
    }
    DEBUG_ASSERT(index < RISCV64_SV_ENTRIES_PER_LEVEL);
    return index;
}
 
static int
riscv64_paging_get_entry_flags(int level,
                           void *entry_data,
                           unsigned long *flags_out)
{
    unsigned long flags = 0;
    uint64_t entry = *(uint64_t *)entry_data;

    if(!(entry & RISCV64_SV_VALID)) {
        *flags_out = PAGING_ENTRY_IS_LEAF;
        return 0;
    }

    int is_leaf = RISCV64_SV_ENTRY_IS_LEAF(entry);

    DEBUG_ASSERT(level > 0 || is_leaf);

    flags |= (entry & RISCV64_SV_VALID) ? PAGING_ENTRY_PRESENT : 0;
    flags |= (entry & RISCV64_SV_VMEM_SHARED_MAP) ? PAGING_ENTRY_MAP : 0;

    if(is_leaf)
    {
        flags |= PAGING_ENTRY_IS_LEAF;
        flags |= (entry & RISCV64_SV_READ) ? PAGING_ENTRY_READABLE : 0;
        flags |= (entry & RISCV64_SV_WRITE) ? PAGING_ENTRY_WRITEABLE : 0;
        flags |= (entry & RISCV64_SV_EXEC) ? PAGING_ENTRY_EXECUTABLE : 0;
        flags |= (entry & RISCV64_SV_USER) ? PAGING_ENTRY_USER_ACCESS : 0;
        flags |= PAGING_ENTRY_KERNEL_ACCESS;
    }
    else
    {
        // Mark the entry as fully accessible
        flags |= PAGING_ENTRY_READABLE;
        flags |= PAGING_ENTRY_WRITEABLE;
        flags |= PAGING_ENTRY_EXECUTABLE;
        flags |= PAGING_ENTRY_USER_ACCESS;
        flags |= PAGING_ENTRY_KERNEL_ACCESS;
    }

    *flags_out = flags;

    return 0;
}

static int
riscv64_paging_set_entry_flags(
        int level,
        void *entry_data,
        unsigned long flags)
{
    uint64_t entry = *(uint64_t*)entry_data;
    uint64_t addr_part = entry & ~0x3FFUL;

    entry |= (flags & PAGING_ENTRY_PRESENT) ? RISCV64_SV_VALID : 0;
    entry |= (flags & PAGING_ENTRY_MAP) ? RISCV64_SV_VMEM_SHARED_MAP : 0;

    if(RISCV64_SV_ENTRY_IS_LEAF(entry) || (flags & PAGING_ENTRY_IS_LEAF)) {
        // Table/Leaf -> Leaf
        entry |= (flags & PAGING_ENTRY_READABLE) ? RISCV64_SV_READ : 0;
        entry |= (flags & PAGING_ENTRY_EXECUTABLE) ? RISCV64_SV_EXEC : 0;
        entry |= (flags & PAGING_ENTRY_WRITEABLE) ? RISCV64_SV_WRITE : 0;
        entry |= (flags & PAGING_ENTRY_USER_ACCESS) ? RISCV64_SV_USER : 0;
        if(!RISCV64_SV_ENTRY_IS_LEAF(entry)) {
            entry |= RISCV64_SV_READ;
        }
    }

    entry &= 0x3FFUL;

    DEBUG_ASSERT_MSG(level > 0 || RISCV64_SV_ENTRY_IS_LEAF(entry) || !(entry & RISCV64_SV_VALID),
            "riscv64: invalid leaf entry: 0x%lx", entry);

    *(uint64_t*)entry_data = addr_part | entry;

    return 0;
}

static int
riscv64_paging_clear_entry_flags(
        int level,
        void *entry_data,
        unsigned long flags)
{
    uint64_t entry = *(uint64_t*)entry_data;
    uint64_t addr_part = entry & ~0x3FFUL;

    entry &= ~(flags & PAGING_ENTRY_PRESENT ? RISCV64_SV_VALID : 0);
    entry &= ~(flags & PAGING_ENTRY_MAP ? RISCV64_SV_VMEM_SHARED_MAP : 0);

    if(flags & PAGING_ENTRY_IS_LEAF) {
        if(RISCV64_SV_ENTRY_IS_LEAF(entry)) {
            // Table/Leaf -> Table
            entry &= ~RISCV64_SV_READ;
            entry &= ~RISCV64_SV_EXEC;
            entry &= ~RISCV64_SV_WRITE;
        }
    }

    if(RISCV64_SV_ENTRY_IS_LEAF(entry)) {
        entry &= ~((flags & PAGING_ENTRY_READABLE) ? RISCV64_SV_READ : 0);
        entry &= ~((flags & PAGING_ENTRY_EXECUTABLE) ? RISCV64_SV_EXEC : 0);
        entry &= ~((flags & PAGING_ENTRY_WRITEABLE) ? RISCV64_SV_WRITE : 0);
        entry &= ~((flags & PAGING_ENTRY_USER_ACCESS) ? RISCV64_SV_USER : 0);
        if(!RISCV64_SV_ENTRY_IS_LEAF(entry)) {
            wprintk("RISCV64 cannot clear all access flags on a leaf page table entry!\n");
            return -EINVAL;
        }
    }

    entry &= 0x3FFUL;

    *(uint64_t*)entry_data = addr_part | entry;
    return 0;
}

static int
riscv64_paging_entry_clear(int level, void *entry_data)
{
    *(uint64_t *)entry_data = 0;
    return 0;
}

static int
riscv64_paging_read_entry_addr(int level, void *entry_data, void __phys **addr)
{
    uint64_t entry = *(uint64_t*)entry_data;
    entry &= ~0x3FFUL; // Mask out bottom 10 bits
    entry <<= 2; // RISC-V is annoying about this...
    *addr = (void __phys *)entry;
    return 0;
}

static int
riscv64_paging_write_entry_addr(int level, void *entry_data, void __phys *addr)
{
    uint64_t entry = *(uint64_t*)entry_data;
    uint64_t flags = entry & 0x3FFUL; // Save the bottom bits
    uint64_t ppn = (((uint64_t)addr) >> 2) & ~0x3FFUL;
    entry = flags | ppn;
    *(uint64_t*)entry_data = entry;
    return 0;
}

static struct paging_mode riscv64_paging_mode = {
    .num_levels = NUM_LEVELS,
    .level_num_entries_order = riscv64_level_num_entries_order,
    .level_entry_order = riscv64_level_entry_order,
    .level_entry_region_order = riscv64_level_entry_region_order,
    .level_flags = riscv64_level_flags,

    .level_addr_table_index = riscv64_paging_level_addr_table_index,
    .get_entry_flags = riscv64_paging_get_entry_flags,
    .set_entry_flags = riscv64_paging_set_entry_flags,
    .clear_entry_flags = riscv64_paging_clear_entry_flags,
    .clear_entry = riscv64_paging_entry_clear,
    .read_entry_addr = riscv64_paging_read_entry_addr,
    .write_entry_addr = riscv64_paging_write_entry_addr,
};

const struct paging_mode *
arch_paging_mode(void)
{
    return &riscv64_paging_mode;
}

uint64_t
riscv64_vmem_map_get_satp(
        struct vmem_map *map)
{
    void __phys *root_table;
    int root_level;

#ifdef CONFIG_RISCV64_IMPLEMENT_VMEM_DIRECTLY
    root_table = map->arch_state.root_table;
    root_level = map->arch_state.root_level;
#else
    root_table = pagetable_root(&map->arch_state.paging_state.pagetable);
    root_level = pagetable_root_level(&map->arch_state.paging_state.pagetable);
#endif

    uint64_t satp_value = ((uintptr_t)root_table >> 12);

    switch(root_level)
    {
    case 2:
        satp_value |= (8ULL << 60);
        break;
    case 3:
        satp_value |= (9ULL << 60);
        break;
    case 4:
        satp_value |= (10ULL << 60);
        break;
    default:
        panic("Trying to format an invalid SATP value!\n");
    }
    return satp_value;
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
arch_paging_set_pt_root(void __phys *pt_root, int root_level)
{
    // TODO: This is a duplicate of "riscv64_vmem_map_get_satp"
    uint64_t satp_value = ((uintptr_t)pt_root >> 12);

    switch(root_level)
    {
    case 2:
        satp_value |= (8ULL << 60);
        break;
    case 3:
        satp_value |= (9ULL << 60);
        break;
    case 4:
        satp_value |= (10ULL << 60);
        break;
    default:
        panic("Trying to format an invalid SATP value!\n");
    }

    write_csr(satp, satp_value);
    riscv64_flush_tlb();
    return 0;
}

int
arch_paging_flush_tlb(void __phys *cond_pt_root, int force)
{
    int irq_flags = disable_save_irqs();
    riscv64_flush_tlb();
    enable_restore_irqs(irq_flags);
    return 0;
}

#endif
