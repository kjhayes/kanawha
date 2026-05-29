
#include <arch/arm64/mmu.h>
#include <arch/arm64/sysreg.h>
#include <kanawha/irq.h>
#include <kanawha/paging/paging.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>

// "TTBR0/1" (two entries) -> L0 (root) -> L3 (4KiB leaf)
#define NUM_LEVELS (5)

const static order_t arm64_level_num_entries_order[] = {
    9, // L3
    9, // L2
    9, // L1
    9, // L0
    1, // Two entries for TTBR0 and TTBR1
};
const static order_t arm64_level_entry_order[] = {
    3, // L3
    3, // L2
    3, // L1
    3, // L0
    3, // TTBR0 and TTBR1
};
const static order_t arm64_level_entry_region_order[] = {
    12,
    21,
    30,
    39,
    48, // TTBR0 and TTBR1
};
const static unsigned long arm64_level_flags[] = {
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0 | PAGING_LEVEL_FLAG_CAN_BE_LEAF,
    0, // L0 cannot be a leaf
    0 | PAGING_LEVEL_FLAG_SPECIAL, // TTBR0 and TTBR1 cannot be leaves
};

static size_t
arm64_paging_level_addr_table_index(int level, void *addr)
{
    uintptr_t shifted = (uintptr_t)addr >> arm64_level_entry_region_order[level];
    if(level == 4) {
        if((shifted & 0xFFFF) == 0xFFFF) {
            return 1;
        } else if(shifted == 0) {
            return 0;
        } else {
            wprintk("arm64_paging_level_addr_table_index: given a non-canonical address! (treating as high-mem) (addr=%p)",
                    addr);
            return 1;
        }
    } else {
        size_t index = shifted & ((1UL<<arm64_level_num_entries_order[level])-1);
        return index;
    }
}

static int
arm64_paging_get_entry_flags(int level,
                           void *entry_data,
                           unsigned long *flags_out)
{
    uint64_t entry = *(uint64_t*)entry_data;
    unsigned long flags = 0;

    if(level == 4) {
        // TTBR0 or TTBR1
        if(entry == 0) {
            flags = 0;
        } else {
            flags = PAGING_ENTRY_PRESENT
                  |PAGING_ENTRY_READABLE
                  |PAGING_ENTRY_WRITEABLE
                  |PAGING_ENTRY_EXECUTABLE
                  |PAGING_ENTRY_KERNEL_ACCESS
                  ;
        }
        if(flags_out) {
            *flags_out = flags;
        }
        return 0;
    }
 
    if(!(entry & 1)) {
        // Present Flag is Cleared
        if(flags_out) {
            *flags_out = 0;
        }
        return 0;
    }

    if(entry & 0b10) {
        if(level == 0) {
            // Leaf
            if(entry & (1UL<<10)) { // Access Flag
                flags |= PAGING_ENTRY_PRESENT;
            }
            flags |= PAGING_ENTRY_IS_LEAF;
            flags |= PAGING_ENTRY_KERNEL_ACCESS;

            if(entry & (1UL<<6)) {
                flags |= PAGING_ENTRY_USER_ACCESS;
            }
            if(entry & (1UL<<7)) {
                // Readonly Set
                flags |= PAGING_ENTRY_READABLE;
            } else {
                flags |= PAGING_ENTRY_READABLE;
                flags |= PAGING_ENTRY_WRITEABLE;
            }
            if(!((entry & (1ULL<<53)) || (entry & (1ULL<<54)))) {
                flags |= PAGING_ENTRY_EXECUTABLE;
            }
            if(entry & (1ULL<<55)) {
                flags |= PAGING_ENTRY_MAP;
            }
            uint8_t mair_index = (entry >> 2) & 0b111;
            switch(mair_index) {
                case ARM64_MAIR_INDEX_NORMAL_CACHEABLE:
                    break;
                case ARM64_MAIR_INDEX_DEVICE_UNCACHEABLE:
                default:
                    flags |= PAGING_ENTRY_CACHE_DISABLE;
                    break;
            }
        } else {
            // Table
            flags |= PAGING_ENTRY_PRESENT;
            flags |= PAGING_ENTRY_READABLE;
            flags |= PAGING_ENTRY_WRITEABLE;
            flags |= PAGING_ENTRY_EXECUTABLE;
            flags |= PAGING_ENTRY_KERNEL_ACCESS;

            if(entry & (1ULL<<55)) {
                flags |= PAGING_ENTRY_MAP;
            }
        }
    } else {
        if(level != 0) {
            // Block
            if(entry & (1UL<<10)) { // Access Flag
                flags |= PAGING_ENTRY_PRESENT;
            }
            flags |= PAGING_ENTRY_IS_LEAF;
            flags |= PAGING_ENTRY_KERNEL_ACCESS;

            if(entry & (1UL<<6)) {
                flags |= PAGING_ENTRY_USER_ACCESS;
            }
            if(entry & (1UL<<7)) {
                // Readonly Set
                flags |= PAGING_ENTRY_READABLE;
            } else {
                flags |= PAGING_ENTRY_READABLE;
                flags |= PAGING_ENTRY_WRITEABLE;
            }
            if(!((entry & (1ULL<<53)) || (entry & (1ULL<<54)))) {
                flags |= PAGING_ENTRY_EXECUTABLE;
            }
            if(entry & (1ULL<<55)) {
                flags |= PAGING_ENTRY_MAP;
            }
            uint8_t mair_index = (entry >> 2) & 0b111;
            switch(mair_index) {
                case ARM64_MAIR_INDEX_NORMAL_CACHEABLE:
                    break;
                case ARM64_MAIR_INDEX_DEVICE_UNCACHEABLE:
                default:
                    flags |= PAGING_ENTRY_CACHE_DISABLE;
                    break;
            }
        } else {
            // Invalid (Block at L3)
            wprintk("Found invalid block at L3 of arm64 page table!\n");
            return -EINVAL;
        }
    }
    
    if(flags_out) {
        *flags_out = flags;
    }

    return 0;
}

static int
arm64_paging_set_entry_flags(int level, void *entry_data, unsigned long flags)
{
    uint64_t entry = *(uint64_t*)entry_data;

    if(level == 4) {
        return 0;
    }

    int is_present = (entry & 1);
    int is_leaf = ((level == 0) || (is_present && !(entry & 0b10)));

    if(!is_leaf && (flags & PAGING_ENTRY_IS_LEAF)) {
        // Table -> Block (cannot be a level 0 entry)
        entry &= ~0x0000000000000FFEULL; // Clear bits [11:1]
        entry &= ~0xFFFF000000000000ULL; // Clear high-order bits
        is_leaf = 1;
    }

    if(flags & PAGING_ENTRY_PRESENT) {
        if(is_leaf && ((entry & 1) == 0)) {
            // We were not present before, mark the page
            // readonly and unexecutable for now.
            entry |= (1ULL<<7);
            entry |= (1ULL<<53);
            entry |= (1ULL<<54);
        }
        entry |= 1ULL;
    }

    if(is_leaf) {
        if(level == 0) {
            entry |= 1ULL<<1; // Properly Mark this as a Leaf Entry
            if(flags & PAGING_ENTRY_PRESENT) {
                entry |= (1ULL<<0); // Present
                entry |= (1ULL<<10); // Access
                entry |= (1ULL<<9); // Outer Shareable
            }
            if(flags & PAGING_ENTRY_MAP) {
                entry |= (1ULL<<55);
            }
            if(flags & PAGING_ENTRY_USER_ACCESS) {
                entry |= (1ULL<<6);
            }
            if(flags & PAGING_ENTRY_WRITEABLE) {
                entry &= ~(1ULL<<7);
            }
            if(flags & PAGING_ENTRY_EXECUTABLE) {
                entry &= ~(1ULL<<53);
                entry &= ~(1ULL<<54);
            }
            if(flags & PAGING_ENTRY_CACHE_DISABLE) {
                entry &= ~(0x7UL<<2);
                entry |= (ARM64_MAIR_INDEX_DEVICE_UNCACHEABLE)<<2;
            }
        } else {
            // Block
            entry &= ~(1ULL<<1); // Properly Mark this as a Block Entry
            if(flags & PAGING_ENTRY_PRESENT) {
                entry |= (1ULL<<0); // Present 
                entry |= (1ULL<<10); // Access
                entry |= (1ULL<<9); // Outer Shareable
            }
            if(flags & PAGING_ENTRY_MAP) {
                entry |= (1ULL<<55);
            }
            if(flags & PAGING_ENTRY_USER_ACCESS) {
                entry |= (1ULL<<6);
            }
            if(flags & PAGING_ENTRY_WRITEABLE) {
                entry &= ~(1ULL<<7);
            }
            if(flags & PAGING_ENTRY_EXECUTABLE) {
                entry &= ~(1ULL<<53);
                entry &= ~(1ULL<<54);
            }
            if(flags & PAGING_ENTRY_CACHE_DISABLE) {
                entry &= ~(0x7UL<<2);
                entry |= (ARM64_MAIR_INDEX_DEVICE_UNCACHEABLE)<<2;
            }
        }
    } else {
        entry |= (1ULL<<1); // Properly Mark this as a Table entry
        if(flags & PAGING_ENTRY_PRESENT) {
            entry |= (1ULL<<0); // Present 
        }
        if(flags & PAGING_ENTRY_MAP) {
            entry |= (1ULL<<55);
        }
    }

    dprintk("Setting flags level %d -> 0x%lx\n",
            level, entry);

    *(uint64_t*)entry_data = entry;
    return 0;
}

static int
arm64_paging_clear_entry_flags(int level, void *entry_data, unsigned long flags)
{
    uint64_t entry = *(uint64_t*)entry_data;

    if(flags & PAGING_ENTRY_PRESENT) {
        entry = 0ULL;
        *(uint64_t*)entry_data = entry; 
        return 0;
    }

    if(level == 4) {
        return 0;
    }

    int is_leaf = (level == 0) || !(entry & 0b10);

    if(is_leaf && (flags & PAGING_ENTRY_IS_LEAF)) {
        if(level == 0) {
            dprintk("Cannot clear LEAF from level 0 page table entry!\n");
            return -EINVAL;
        }
        // Block -> Table (setup a basic table descriptor)
        entry &= ~0x0000000000000FFEULL; // Clear bits [11:1]
        entry &= ~0xFFFF000000000000ULL; // Clear high-order bits
        entry |= 0b10; // Mark this as a table
        is_leaf = 0;
    }

    if(flags & PAGING_ENTRY_READABLE) {
        eprintk("arm64_paging_clear_entry_flags: cannot clear PAGING_ENTRY_READABLE!\n");
        return -EINVAL;
    }

    if(flags & PAGING_ENTRY_PRESENT) {
        entry &= ~1ULL;
    }

    if(is_leaf) {
        if(level == 0) {
            // Leaf
            if(flags & PAGING_ENTRY_PRESENT) {
                entry &= ~(1ULL<<10); // Access
            }
            if(flags & PAGING_ENTRY_MAP) {
                entry &= ~(1ULL<<55);
            }
            if(flags & PAGING_ENTRY_USER_ACCESS) {
                entry &= ~(1ULL<<6);
            }
            if(flags & PAGING_ENTRY_WRITEABLE) {
                entry |= (1ULL<<7);
            }
            if(flags & PAGING_ENTRY_EXECUTABLE) {
                entry |= (1ULL<<53);
                entry |= (1ULL<<54);
            }
            if(flags & PAGING_ENTRY_CACHE_DISABLE) {
                flags &= ~(0x7UL<<2);
                flags |= (ARM64_MAIR_INDEX_NORMAL_CACHEABLE)<<2;
            }
        } else {
            // Block
            if(flags & PAGING_ENTRY_PRESENT) {
                entry &= ~(1ULL<<10); // Access
            }
            if(flags & PAGING_ENTRY_MAP) {
                entry &= ~(1ULL<<55);
            }
            if(flags & PAGING_ENTRY_USER_ACCESS) {
                entry &= ~(1ULL<<6);
            }
            if(flags & PAGING_ENTRY_WRITEABLE) {
                entry |= (1ULL<<7);
            }
            if(flags & PAGING_ENTRY_EXECUTABLE) {
                entry |= (1ULL<<53);
                entry |= (1ULL<<54);
            }
            if(flags & PAGING_ENTRY_CACHE_DISABLE) {
                flags &= ~(0x7UL<<2);
                flags |= (ARM64_MAIR_INDEX_NORMAL_CACHEABLE)<<2;
            }
        }
    } else {
        // Table
        if(flags & PAGING_ENTRY_MAP) {
            entry &= ~(1ULL<<55);
        }
    }

    *(uint64_t*)entry_data = entry;
    return 0;
}

static int
arm64_paging_entry_clear(int level, void *entry_data)
{
    uint64_t entry = 0;
    *(uint64_t *)entry_data = entry;
    return 0;
}

static int
arm64_paging_read_entry_addr(int level, void *entry_data, void __phys **addr)
{
    uint64_t entry = *(uint64_t*)entry_data;
    uint64_t mask = 0;
    if(level == 4) {
        // TTBR0 or TTBR1
        mask = 0x0000FFFFFFFFFFFEULL;
    } else {
        mask = 0x0000FFFFFFFFF000ULL;
    }
    if(addr) {
        *addr = (void __phys *)(uint64_t)(entry & mask);
    }
    return 0;
}

static int
arm64_paging_write_entry_addr(int level, void *entry_data, void __phys *addr)
{
    uint64_t entry = *(uint64_t*)entry_data;
    uint64_t mask = 0;
    if(level == 4) {
        // TTBR0 or TTBR1
        mask = 0x0000FFFFFFFFFFFEULL;
        entry = 0;
    } else {
        mask = 0x0000FFFFFFFFF000ULL;
    }
    entry &= ~mask;
    entry |= (((uint64_t)addr) & mask);
    *(uint64_t*)entry_data = entry;
    dprintk("arm64_paging_write_entry_addr: level %d -> %p\n",
            level, addr);
    return 0;
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
    if(level != 4) {
        eprintk("arm64_paging_set_pt_root: cannot set level %d as pagetable root!\n");
        return -EINVAL;
    }

    uint64_t *root_table = __va(pt_root);
    uint64_t ttbr0_el1 = root_table[0];
    uint64_t ttbr1_el1 = root_table[1];

    dprintk("arch_paging_set_pt_root: ttbr0_el1=%p\n", (void __phys *)ttbr0_el1);
    dprintk("arch_paging_set_pt_root: ttbr1_el1=%p\n", (void __phys *)ttbr1_el1);

    arm64_sysreg_writeq(TTBR0_EL1, ttbr0_el1);
    arm64_sysreg_writeq(TTBR1_EL1, ttbr1_el1);

    return 0;
}

int
arch_paging_flush_tlb(void __phys *cond_pt_root, int force)
{
    // I'm not certain that this is correct -KJH
    // asm volatile ("TLBI VMALLE1; DSB ISH; ISB");
    return 0;
}
#endif

static int
arm64_init_paging_configuration(void) {
    uint64_t sctlr_el1 = arm64_sysreg_readq(SCTLR_EL1);
    sctlr_el1 &= ~(1ULL<<19); // Disable "Write Execute Never (WXN)" bit
    arm64_sysreg_writeq(SCTLR_EL1, sctlr_el1);
    uint64_t mair_el1 = arm64_sysreg_readq(MAIR_EL1);
    mair_el1 = ARM64_MAIR_DEFAULT_VALUE;
    arm64_sysreg_writeq(MAIR_EL1, mair_el1);
    return 0;
}
declare_init(vmem, arm64_init_paging_configuration);

