
#include <kanawha/vmem.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/excp.h>
#include <kanawha/irq_domain.h>
#include <kanawha/xcall.h>
#include <kanawha/thread.h>
#include <kanawha/assert.h>
#include <arch/x64/sysreg.h>
#include <arch/x64/exception.h>

#include <arch/x64/mmu.h>

static struct irq_action *x64_pf_action = NULL;

static int
x64_vmem_page_fault_handler(
        struct excp_state *gen_excp_state,
        struct irq_action *action)
{
    int res;

    uintptr_t faulting_address = (uintptr_t)read_cr2();
    struct vmem_map *current = vmem_map_get_current();

    struct x64_excp_state *excp_state =
        (struct x64_excp_state*)gen_excp_state;

    unsigned long pf_flags = 0;

    pf_flags |= (excp_state->error_code & (1ULL<<0)) == 0 ? PF_FLAG_NOT_PRESENT : 0;
    pf_flags |= (excp_state->error_code & (1ULL<<1)) == 0 ? PF_FLAG_READ : 0;
    pf_flags |= excp_state->error_code & (1ULL<<1) ? PF_FLAG_WRITE : 0;
    pf_flags |= excp_state->error_code & (1ULL<<2) ? PF_FLAG_USERMODE : 0;
    pf_flags |= excp_state->error_code & (1ULL<<4) ? PF_FLAG_EXEC : 0;

    res = vmem_map_handle_page_fault(faulting_address, pf_flags, current);

    if(res) {
        
        // Kernel Fault ((noreturn))
        eprintk("x64_vmem_page_fault_handler: Failed to handle page fault (err=%s)\n",
                errnostr(res));

        x64_unhandled_exception((struct x64_excp_state *)excp_state);

        // This should never happen but let's be safe
        return -EINVAL;
    }

    dprintk("Page Fault Handled!\n");
    return IRQ_HANDLED;
}

static int
x64_install_page_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL) {
        return -EDEFER;
    }

    x64_pf_action =
        irq_install_handler(
            x64_vector_irq_desc(14),
            NULL, // Device
            x64_vmem_page_fault_handler);

    if(x64_pf_action == NULL) {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic, x64_install_page_fault_handler, "Installing x64 Page Fault Handler");

static int
x64_virt_flags_static_init(void) {
    int res;

    struct mem_flags *vflags = get_virt_mem_flags();
    printk("Setting Region [%p - %p) as Canonical Low Memory\n",
            0x0,
            X64_PML4_LOWMEM_SIZE);

    res = mem_flags_clear_flags(
            vflags,
            0x0,
            X64_PML4_LOWMEM_SIZE,
            VIRT_MEM_FLAGS_NONCANON);
    if(res) {
        return res;
    }

    printk("Setting Region [%p - %p) as Canonical High Memory\n",
            X64_PML4_HIGHMEM_BASE,
            X64_PML4_HIGHMEM_BASE + (X64_PML4_HIGHMEM_SIZE-1));

    res = mem_flags_clear_flags(
            vflags,
            X64_PML4_HIGHMEM_BASE,
            X64_PML4_HIGHMEM_SIZE-1,
            VIRT_MEM_FLAGS_NONCANON);
    if(res) {
        return res;
    }

    res = mem_flags_set_flags(
            vflags,
            X64_PML4_HIGHMEM_BASE,
            X64_PML4_HIGHMEM_SIZE-1,
            VIRT_MEM_FLAGS_HIGHMEM);
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(mem_flags, x64_virt_flags_static_init, "Setting x64 Virtual Memory Types");

static inline size_t
pt_level_table_index(int level, vaddr_t addr) {
    switch(level) {
        case 1: return X64_PT_INDEX_OF_ADDR(addr);
        case 2: return X64_PD_INDEX_OF_ADDR(addr);;
        case 3: return X64_PDPT_INDEX_OF_ADDR(addr);
        case 4: return X64_PML4_INDEX_OF_ADDR(addr);
        case 5: return X64_PML5_INDEX_OF_ADDR(addr);
        default:
            panic("pt_level_table_index: invalid pt_level (%d)\n", level);
    }
    return 0;
}

static inline size_t
pt_level_num_table_entries(int level) {
    switch(level) {
        case 1: return X64_PT_ENTRIES;
        case 2: return X64_PD_ENTRIES;
        case 3: return X64_PDPT_ENTRIES;
        case 4: return X64_PML4_ENTRIES;
        case 5: return X64_PML5_ENTRIES;
        default:
            panic("pt_level_num_table_entries: invalid pt_level (%d)\n", level);
    }
}

static inline size_t
pt_level_table_size(int level) {
    switch(level) {
        case 1: return X64_PT_SIZE;
        case 2: return X64_PD_SIZE;
        case 3: return X64_PDPT_SIZE;
        case 4: return X64_PML4_SIZE;
        case 5: return X64_PML5_SIZE;
        default:
            panic("pt_level_table_size: invalid pt_level (%d)\n", level);
    }
}

static inline size_t
pt_level_entry_region_size(int level) {
    switch(level) {
        case 1: return X64_PT_ENTRY_REGION_SIZE;
        case 2: return X64_PD_ENTRY_REGION_SIZE;
        case 3: return X64_PDPT_ENTRY_REGION_SIZE;
        case 4: return X64_PML4_ENTRY_REGION_SIZE;
        case 5: return X64_PML5_ENTRY_REGION_SIZE;
        default:
            panic("pt_level_entry_region_size: invalid pt_level (%d)\n", level);
    }
}

static inline uint64_t
pt_level_present_mask(int level) {
    switch(level) {
        case 1: return X64_PT_LEAF_PRESENT;
        case 2: return X64_PD_ENTRY_PRESENT;
        case 3: return X64_PDPT_ENTRY_PRESENT;
        case 4: return X64_PML4_ENTRY_PRESENT;
        case 5: return X64_PML5_ENTRY_PRESENT;
        default:
            panic("pt_level_present_mask: invalid pt_level (%d)\n", level);
    }
}

static inline uint64_t
pt_level_addr_mask(int level) {
    switch(level) {
        case 1: return X64_PT_LEAF_ADDR_MASK;
        case 2: return X64_PD_ENTRY_ADDR_MASK;
        case 3: return X64_PDPT_ENTRY_ADDR_MASK;
        case 4: return X64_PML4_ENTRY_ADDR_MASK;
        case 5: return X64_PML5_ENTRY_ADDR_MASK;
        default:
            panic("pt_level_addr_mask: invalid pt_level (%d)\n", level);
    }
}

static inline int
pt_level_shared_mask(int level, uint64_t *out) {
    switch(level) {
        case 2: *out = X64_PD_ENTRY_VMEM_SHARED_MAP; break;
        case 3: *out = X64_PDPT_ENTRY_VMEM_SHARED_MAP; break;
        case 4: *out = X64_PML4_ENTRY_VMEM_SHARED_MAP; break;
        case 5: *out = X64_PML5_ENTRY_VMEM_SHARED_MAP; break;
        default:
            eprintk("pt_level_shared_mask: invalid pt_level (%d)\n", level);
            return -EINVAL;
    }
    return 0;
}

static inline int
pt_level_entry_can_be_leaf(int level) {

    switch(level) {
        case 1: 
            return 1;
        case 2: 
#ifdef CONFIG_X64_ASSUME_2MB_PAGES
            return 1;
#else
            return 0;
#endif
        case 3:
#ifdef CONFIG_X64_ASSUME_1GB_PAGES
            return 1;
#else
            return 0;
#endif
        case 4: 
        case 5: return 0; 
        default:
            panic("pt_level_entry_can_be_leaf: invalid pt_level (%d)\n", level);
    }
}

static inline int
pt_level_entry_is_leaf(int level, uint64_t entry)
{
    int res;

    switch(level) {
        case 1:
            return 1;
        case 2:
            return !!(entry & X64_PD_ENTRY_PAGE_SIZE);
        case 3:
            return !!(entry & X64_PDPT_ENTRY_PAGE_SIZE);
        case 4:
        case 5:
            return 0;
        default:
            panic("pt_level_entry_can_be_leaf: invalid pt_level (%d)\n", level);
    }
}

static inline int
__x64_verify_page_table(
        paddr_t table,
        int level)
{
    int res;

    void *vaddr = (void*)__va(table);
    if(!(KERNEL_ADDR(vaddr))) {
        eprintk("Kernel Page Table Address paddr=%p, vaddr=%p is Invalid!\n",
                (uint64_t)table,
                (uint64_t)vaddr);
        return -EINVAL;
    }

    size_t num_entries = pt_level_num_table_entries(level);
    uint64_t addr_mask = pt_level_addr_mask(level);
    uint64_t present_mask = pt_level_present_mask(level);

    uint64_t *entries = vaddr;
    for(size_t i = 0; i < num_entries; i++) {
        uint64_t entry = entries[i];

        if((entry & present_mask) == 0) {
            continue;
        }

        paddr_t addr = entry & addr_mask;
        void *entry_vaddr = (void*)__va(addr);

        if(!(KERNEL_ADDR(entry_vaddr))) {
            eprintk("Kernel Page Table Entry entry=%p is Invalid!\n");
            return -EINVAL;
        }

        if(!pt_level_entry_is_leaf(level, entry)) {
            res = __x64_verify_page_table(addr, level-1);
            if(res) {
                eprintk("Kernel Page Subtable at Level %d is Invalid!\n",
                        level-1);
                return res;
            }
        }
    }
    return 0;
}

static inline void
x64_verify_page_table(
        paddr_t table,
        int level)
{
#ifndef CONFIG_DEBUG_ASSERTIONS
    return;
#else
    int res;
    res = __x64_verify_page_table(table, level);
    if(res) {
        panic("Failed to verify x64 Page Table paddr=%p vaddr=%p, level=%d\n",
                (uint64_t)table,
                (uint64_t)__va(table),
                level);
    }
#endif
}

int
arch_vmem_map_init(struct vmem_map *map)
{
    int res;

    map->arch_state.pt_level = 0;
    res = page_alloc(ptr_orderof(X64_PML4_SIZE), &map->arch_state.pt_root, 0);
    if(res) {
        return res;
    }

    map->arch_state.pt_level = 4;
    memset((void*)__va(map->arch_state.pt_root), 0, X64_PML4_SIZE);

    x64_verify_page_table(map->arch_state.pt_root, map->arch_state.pt_level);

    return 0;
}

// Every region should have been unmapped from this map already
int
arch_vmem_map_deinit(struct vmem_map *map)
{
    int res;
    if(map->arch_state.pt_level <= 3) {
        eprintk("Trying to deinit vmem_map with pt_level %d!\n", map->arch_state.pt_level);
        return -EINVAL;
    }

    res = page_free(ptr_orderof(X64_PML4_SIZE), map->arch_state.pt_root);
    if(res) {
        return res;
    }

    return 0;
}

static int
create_pt_leaf_entry(
        uint64_t *entry,
        int pt_level,
        paddr_t base,
        unsigned long flags)
{
    *entry = 0;
    *entry |= (uintptr_t)base;

    if((flags & VMEM_REGION_READ) == 0) {
        eprintk("Cannot map non-readable vmem region on x64!\n");
        return -EINVAL;
    }

    switch(pt_level) {
        case 1:
            *entry |= X64_PT_LEAF_PRESENT;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PT_LEAF_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PT_LEAF_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PT_LEAF_WRITE : 0;
            *entry |= flags & VMEM_REGION_NOCACHE ? X64_PT_LEAF_CACHE_DISABLE : 0;
            break;
        case 2:
            *entry |= X64_PD_LEAF_PRESENT;
            *entry |= X64_PD_LEAF_PAGE_SIZE;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PD_LEAF_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PD_LEAF_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PD_LEAF_WRITE : 0; 
            *entry |= flags & VMEM_REGION_NOCACHE ? X64_PD_LEAF_CACHE_DISABLE : 0;
            break;
        case 3:
            *entry |= X64_PDPT_LEAF_PRESENT;
            *entry |= X64_PDPT_LEAF_PAGE_SIZE;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PDPT_LEAF_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PDPT_LEAF_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PDPT_LEAF_WRITE : 0; 
            *entry |= flags & VMEM_REGION_NOCACHE ? X64_PDPT_LEAF_CACHE_DISABLE : 0;
            break;
        default:
            eprintk("create_pt_leaf_entry: invalid pt_level (%d)\n", pt_level);
            return -EINVAL;
    }
    
    return 0;
}

static int
create_permissive_pt_table_entry(
        uint64_t *entry,
        int pt_level,
        paddr_t next_table)
{
    x64_verify_page_table(next_table, pt_level-1);

    *entry = 0;

    DEBUG_ASSERT(ptr_orderof(next_table) >= 12);

    *entry |= (uintptr_t)next_table;

    // Be as permissive as possible because restrictions are inherited
    switch(pt_level) {
        case 2:
            *entry |= X64_PD_ENTRY_PRESENT;
            *entry |= X64_PD_ENTRY_USER;
            *entry |= X64_PD_ENTRY_WRITE; 
            break;
        case 3:
            *entry |= X64_PDPT_ENTRY_PRESENT;
            *entry |= X64_PDPT_ENTRY_USER;
            *entry |= X64_PDPT_ENTRY_WRITE;
            break;
        case 4:
            *entry |= X64_PML4_ENTRY_PRESENT;
            *entry |= X64_PML4_ENTRY_USER;
            *entry |= X64_PML4_ENTRY_WRITE;
            break; 
        default:
            eprintk("create_permissive_pt_table_entry: invalid pt_level (%d)\n", pt_level);
            return -EINVAL;
    }
    return 0;
}

static int
create_shared_pt_table_entry(
        uint64_t *entry,
        int pt_level,
        paddr_t next_table)
{
    x64_verify_page_table(next_table, pt_level-1);

    int res = create_permissive_pt_table_entry(
            entry, pt_level, next_table);
    if(res) {
        return res;
    }

    switch(pt_level) {
        case 2:
            // Mark this as a shared vm_map page table
            *entry |= X64_PD_ENTRY_VMEM_SHARED_MAP;
            break;
        case 3:
            *entry |= X64_PDPT_ENTRY_VMEM_SHARED_MAP;
            break;
        case 4:
            *entry |= X64_PML4_ENTRY_VMEM_SHARED_MAP;
            break; 
        default:
            eprintk("create_shared_pt_table_entry: invalid pt_level (%d)\n", pt_level);
            return -EINVAL;
    }
    return 0;
}

static int
create_pt_table_entry(
        uint64_t *entry,
        int pt_level,
        paddr_t next_table,
        unsigned long flags)
{
    x64_verify_page_table(next_table, pt_level-1);

    *entry = 0;
    *entry |= next_table;

    switch(pt_level) {
        case 2:
            *entry |= X64_PD_ENTRY_PRESENT;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PD_ENTRY_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PD_ENTRY_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PD_ENTRY_WRITE : 0; 
            break;
        case 3:
            *entry |= X64_PDPT_ENTRY_PRESENT;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PDPT_ENTRY_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PDPT_ENTRY_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PDPT_ENTRY_WRITE : 0; 
            break;
        case 4:
            *entry |= X64_PML4_ENTRY_PRESENT;
            //*entry |= flags & VMEM_REGION_EXEC ? 0 : X64_PML4_ENTRY_EXEC_DISABLE;
            *entry |= flags & VMEM_REGION_USER ? X64_PML4_ENTRY_USER : 0;
            *entry |= flags & VMEM_REGION_WRITE ? X64_PML4_ENTRY_WRITE : 0; 
            break;           
        default:
            eprintk("create_pt_table_entry: invalid pt_level (%d)\n", pt_level);
            return -EINVAL;
    }
    return 0;
}

static int
create_empty_pt_table(
        paddr_t *table_ptr,
        int table_level) 
{
    int res;

    size_t table_size = pt_level_table_size(table_level);
    
    switch(table_level) {
        case 1:
        case 2:
        case 3:
        case 4:
            break;
        default:
            eprintk("create_empty_pt_table: invalid pt_level (%d)\n", table_level);
            return -EINVAL;
    }

    res = page_alloc(ptr_orderof(table_size), table_ptr, 0);
    if(res) {
        return -ENOMEM;
    }
    memset((void*)__va(*table_ptr), 0, table_size);

    x64_verify_page_table(*table_ptr, table_level);

    return 0;
}

static int
create_paged_pt_table(
        paddr_t *table_ptr,
        int table_level,
        size_t size)
{
    int res;

    size_t entry_region_size;
    size_t num_possible_entries;

    if(table_level <= 1) {
        return -EINVAL;
    }

    num_possible_entries = pt_level_num_table_entries(table_level);
    entry_region_size = pt_level_entry_region_size(table_level);
  
    // If we fail later we don't actually free this (TODO)
    res = create_empty_pt_table(table_ptr, table_level);
    if(res) {
        return res;
    }
 
    // Map in the region as if we started at the virtual base of this table
    size_t num_whole_entries = size / entry_region_size;

    for(size_t i = 0; i < num_whole_entries; i++) {
        // Map the middle entries
        paddr_t subtable;
        res = create_empty_pt_table(
                &subtable,
                table_level-1);
        if(res) {
            return res;
        }
        res = create_permissive_pt_table_entry(
                ((uint64_t*)__va(*table_ptr)) + i,
                table_level,
                subtable);
        if(res) {
            return res;
        }
    }

    size_t final_entry_size = size - (num_whole_entries*entry_region_size);
    if(final_entry_size > 0) 
    {
      paddr_t subtable;
      res = create_paged_pt_table(
              &subtable,
              table_level-1,
              final_entry_size);
      if(res) {
          return res;
      }
      res = create_permissive_pt_table_entry(
              ((uint64_t*)__va(*table_ptr)) + num_whole_entries,
              table_level,
              subtable);
      if(res) {
          return res;
      }
    }

    x64_verify_page_table(*table_ptr, table_level);
    return 0;

}

static int
create_direct_pt_table(
        paddr_t *table_ptr,
        int table_level,
        paddr_t base,
        size_t size,
        unsigned long flags) 
{
    int res;

    size_t entry_region_size;
    size_t num_possible_entries;
    int entry_can_be_leaf;

    num_possible_entries = pt_level_num_table_entries(table_level);
    entry_region_size = pt_level_entry_region_size(table_level);
    entry_can_be_leaf = pt_level_entry_can_be_leaf(table_level);
  
    // If we fail later we don't actually free this (TODO)
    res = create_empty_pt_table(table_ptr, table_level);
    if(res) {
        return res;
    }

    // Map in the region as if we started at the virtual base of this table
    size_t num_whole_entries = size / entry_region_size;

    for(size_t i = 0; i < num_whole_entries; i++) {
        // Map the middle entries
        if(entry_can_be_leaf) {
            res = create_pt_leaf_entry(
                    ((uint64_t*)__va(*table_ptr)) + i,
                    table_level,
                    base + (entry_region_size * i),
                    flags);
            if(res) {
                return res;
            }
        } else {
            paddr_t subtable;
            res = create_direct_pt_table(
                    &subtable,
                    table_level-1,
                    base + (entry_region_size * i),
                    entry_region_size,
                    flags);
            if(res) {
                return res;
            }
            res = create_pt_table_entry(
                    ((uint64_t*)__va(*table_ptr)) + i,
                    table_level,
                    subtable,
                    flags);
            if(res) {
                return res;
            }
        }
    }

    size_t final_entry_size = size - (num_whole_entries*entry_region_size);

    if(final_entry_size > 0) {
      // We need to map the first entry as a table
      paddr_t subtable;
      res = create_direct_pt_table(
              &subtable,
              table_level-1,
              base + (num_whole_entries*entry_region_size),
              final_entry_size,
              flags);
      if(res) {
          return res;
      }
      res = create_pt_table_entry(
              ((uint64_t*)__va(*table_ptr)) + num_whole_entries,
              table_level,
              subtable,
              flags);
      if(res) {
          return res;
      }
    }

    x64_verify_page_table(*table_ptr, table_level);

    return 0;
}

static int
arch_vmem_region_init_direct(struct vmem_region *region)
{
    int res;

    if(region->direct.phys_base % X64_PT_ENTRY_REGION_SIZE != 0) {
        eprintk("Tried to initialize direct region with physical base unaligned from smallest page size!\n"
                "    region_base=%p, min_page_size=%p\n", region->direct.phys_base, (uintptr_t)X64_PT_ENTRY_REGION_SIZE);
        return -EINVAL;
    }
    if(region->size % X64_PT_ENTRY_REGION_SIZE != 0) {
        eprintk("Tried to initialize direct region with size that isn't a multiple of the smallest page size!\n",
                "    region_size=%p, min_page_size=%p\n", region->size, (uintptr_t)X64_PT_ENTRY_REGION_SIZE);
        return -EINVAL;
    }

    paddr_t base = region->direct.phys_base;
    paddr_t end = base + (region->size-1);

    region->arch_state.pt_level = -1;
    size_t pt_level_entry_size = -1;
    int can_be_leaf = 0;

    if((region->size <= X64_PD_ENTRY_REGION_SIZE) 
     &&(base / X64_PD_ENTRY_REGION_SIZE == end / X64_PD_ENTRY_REGION_SIZE))
    {
      // We can fit inside a single PT
      region->arch_state.pt_level = 1;
      pt_level_entry_size = X64_PT_ENTRY_REGION_SIZE;
      can_be_leaf = 1;
    }

    if((region->size <= X64_PDPT_ENTRY_REGION_SIZE)
     &&(base / X64_PDPT_ENTRY_REGION_SIZE == end / X64_PDPT_ENTRY_REGION_SIZE))
    {
      // We can fit inside a single PD
      region->arch_state.pt_level = 2;
      pt_level_entry_size = X64_PD_ENTRY_REGION_SIZE;
      can_be_leaf = 1;
    }

    if((region->size <= X64_PML4_ENTRY_REGION_SIZE) 
     &&(base / X64_PML4_ENTRY_REGION_SIZE == end / X64_PML4_ENTRY_REGION_SIZE))
    {
      // We can fit inside a single PDPT
      region->arch_state.pt_level = 3;
      pt_level_entry_size = X64_PDPT_ENTRY_REGION_SIZE;
      can_be_leaf = 1;
    }

    if(region->arch_state.pt_level < 1 || region->arch_state.pt_level > 3) {
        eprintk("Could not find a page table level which would work for vmem_region [%p - %p)!\n",
                (uintptr_t)region->direct.phys_base, (uintptr_t)(region->direct.phys_base + region->size));
        return -EINVAL;
    }

    if(can_be_leaf && region->size == pt_level_entry_size) {
        region->arch_state.entry_only = 1;
        res = create_pt_leaf_entry(
            &region->arch_state.pt_entry,
            region->arch_state.pt_level,
            base,
            region->direct.flags);
        if(res) {
            return res;
        }
    } else {
        region->arch_state.entry_only = 0;
        res = create_direct_pt_table(
                &region->arch_state.pt_table,
                region->arch_state.pt_level,
                base,
                region->size,
                region->direct.flags);
        if(res) {
            return res;
        }
        res = create_pt_table_entry(
                &region->arch_state.pt_entry,
                region->arch_state.pt_level+1,
                region->arch_state.pt_table,
                region->direct.flags);
        if(res) {
            return res;
        }
    }

    if(region->arch_state.entry_only == 0) {
        x64_verify_page_table(
                region->arch_state.pt_table,
                region->arch_state.pt_level);
    }
    return 0;
}

static int
arch_vmem_region_init_paged(struct vmem_region *region) 
{
    int res;

    if(region->size % X64_PD_ENTRY_REGION_SIZE != 0) {
        eprintk("Tried to initialize paged region with size that isn't a multiple of the smallest page table size!\n",
                "    region_size=%p, min_table_size=%p\n", region->size, (uintptr_t)X64_PD_ENTRY_REGION_SIZE);
        return -EINVAL;
    }

    paddr_t base = 0;
    paddr_t end = (region->size-1);

    region->arch_state.pt_level = -1;
    size_t pt_level_entry_size = -1;

    if((region->size <= X64_PDPT_ENTRY_REGION_SIZE)
     &&(base / X64_PDPT_ENTRY_REGION_SIZE == end / X64_PDPT_ENTRY_REGION_SIZE))
    {
      // We can fit inside a single PD
      region->arch_state.pt_level = 2;
      pt_level_entry_size = X64_PD_ENTRY_REGION_SIZE;
    }

    if((region->size <= X64_PML4_ENTRY_REGION_SIZE) 
     &&(base / X64_PML4_ENTRY_REGION_SIZE == end / X64_PML4_ENTRY_REGION_SIZE))
    {
      // We can fit inside a single PDPT
      region->arch_state.pt_level = 3;
      pt_level_entry_size = X64_PDPT_ENTRY_REGION_SIZE;
    }

    if(region->arch_state.pt_level < 2 || region->arch_state.pt_level > 3) {
        eprintk("Could not find a page table level which would work for paged vmem_region [%p - %p)!\n",
                (uintptr_t)0, (uintptr_t)region->size);
        return -EINVAL;
    }

    region->arch_state.entry_only = 0;
    res = create_paged_pt_table(
            &region->arch_state.pt_table,
            region->arch_state.pt_level,
            region->size);
    if(res) {
        return res;
    }
    res = create_permissive_pt_table_entry(
            &region->arch_state.pt_entry,
            region->arch_state.pt_level+1,
            region->arch_state.pt_table);
    if(res) {
        return res;
    }

    x64_verify_page_table(
            region->arch_state.pt_table,
            region->arch_state.pt_level);

    return 0;
}

int
arch_vmem_region_init(struct vmem_region *region)
{
    switch(region->type) {
        case VMEM_REGION_TYPE_DIRECT:
            return arch_vmem_region_init_direct(region);
        case VMEM_REGION_TYPE_PAGED:
            return arch_vmem_region_init_paged(region);
        default:
            return -EINVAL;
    }
}

static int
map_region_tables(
        paddr_t map_table,
        paddr_t region_table,
        int table_level,
        vaddr_t vbase,
        struct vmem_map *map,
        struct vmem_region *region)
{
    int res;

    size_t table_size;
    size_t level_below_size;
    size_t entry_region_size;
    size_t num_possible_entries;
    size_t level_below_num_possible_entries;
    int entry_must_be_leaf;
    int entry_can_be_leaf;
    size_t vindex;

    uint64_t page_size_mask;
    uint64_t present_mask;
    uint64_t next_table_addr_mask;
    uint64_t shared_table_mask;

    table_size = pt_level_table_size(table_level);
    entry_region_size = pt_level_entry_region_size(table_level);
    num_possible_entries = pt_level_num_table_entries(table_level);
    vindex = pt_level_table_index(table_level, vbase);
    entry_can_be_leaf = pt_level_entry_can_be_leaf(table_level);
    entry_must_be_leaf = (table_level == 1);
    present_mask = pt_level_present_mask(table_level);

    if(table_level > 1) {
        level_below_size = pt_level_table_size(table_level-1);
        level_below_num_possible_entries = pt_level_num_table_entries(table_level-1);
        next_table_addr_mask = pt_level_addr_mask(table_level);
        res = pt_level_shared_mask(table_level, &shared_table_mask);
        if(res) {return res;}
    } else {
        level_below_size = 0;
        level_below_num_possible_entries = 0;
        next_table_addr_mask = 0;
        shared_table_mask = 0;
    }

    switch(table_level) {
        case 2:
            page_size_mask = X64_PD_LEAF_PAGE_SIZE;
            break;
        case 3:
            page_size_mask = X64_PDPT_LEAF_PAGE_SIZE;
            break;
    }

    switch(table_level) {
        case 1:
        case 2:
        case 3:
        case 4:
            break;
        default:
            eprintk("map_region_tables: invalid table_level (%d)\n", table_level);
            return -EINVAL;
    }

    for(size_t vi = vindex; vi < num_possible_entries; vi++) {
        uint64_t *map_entry = &((uint64_t*)__va(map_table))[vi];
        uint64_t *region_entry = &((uint64_t*)__va(region_table))[vi-vindex];

        if(!(*region_entry & present_mask)) {
            // Region isn't present, so this is the end of the region
            break;
        }

        if(!(*map_entry & present_mask)) {
            // Map isn't present, we can map in the region table directly
            dprintk("map_table %p level %lld, entry %lld is not present, overriding\n",
                    map_table, table_level, vi);
            *map_entry = *region_entry;
            continue;
        }

        int map_is_leaf = entry_must_be_leaf ? 1 :
                          entry_can_be_leaf ? *map_entry & page_size_mask : 0;

        int region_is_leaf = entry_must_be_leaf ? 1 :
                             entry_can_be_leaf ? *region_entry & page_size_mask : 0;

        DEBUG_ASSERT(region->type != VMEM_REGION_TYPE_PAGED || !region_is_leaf);

        if(map_is_leaf || region_is_leaf) {
            // OVERLAP!!!
            // We should've caught that already???
            panic("Unexpected vmem region overlap in map_region_tables! (vaddr=%p, table_level=%d)\n",
                    vbase + (entry_region_size * (vi-vindex)), table_level);
            return -EINVAL;
        }

        paddr_t region_next_addr = *region_entry & next_table_addr_mask;
        paddr_t map_next_addr = *map_entry & next_table_addr_mask;

        // They are both tables
        if(!(*map_entry & shared_table_mask)) {
            // the map entry points to some other region's page table
            paddr_t shared_table;
            res = page_alloc(ptr_orderof(level_below_size), &shared_table, 0);
            if(res) {
                return -ENOMEM;
            }

            // Make a copy of the other region's top level table
            memcpy((void*)__va(shared_table), (void*)__va(map_next_addr), level_below_size);

            // Create a shared table entry
            res = create_shared_pt_table_entry(
                    map_entry,
                    table_level,
                    shared_table);
            if(res) {
                return res;
            }
        }

        map_next_addr = *map_entry & next_table_addr_mask;
        
        // Already was or is now a shared page,
        // so we can recursively call ourselves on it
        res = map_region_tables(
                map_next_addr,
                region_next_addr,
                table_level-1,
                vbase + (entry_region_size * (vi-vindex)),
                map,
                region);

        if(res) {
            return res;
        }
    }

    return 0;
}

static int
free_page_tables(
        paddr_t table,
        int level)
{
    int res;

    DEBUG_ASSERT(level > 0 && level <= 5);

    uint64_t *table_entries = (uint64_t*)__va(table);
    size_t num_entries = pt_level_num_table_entries(level);

    uint64_t present_mask = pt_level_present_mask(level);

    for(size_t i = 0; i < num_entries; i++)
    {
        uint64_t entry = table_entries[i];

        // Skip not-present entries
        if((present_mask & entry) == 0) {
            continue;
        }

        // We don't need to do anything for leaf entries
        if(pt_level_entry_is_leaf(level, entry)) {
            continue;
        }

        // This must be a present table
        paddr_t subtable = pt_level_addr_mask(level) & entry;
        res = free_page_tables(subtable, level-1);
        if(res) {
            return res;
        }
    }

    res = page_free(ptr_orderof(pt_level_table_size(level)), table);
    if(res) {
        return res;
    }

    return 0;
}

// This region should not exist in any maps at this point
int
arch_vmem_region_deinit(struct vmem_region *region)
{
    if(region->arch_state.entry_only) {
        return 0;
    } else {
        return free_page_tables(region->arch_state.pt_table, region->arch_state.pt_level);
    }
}

int
arch_vmem_map_map_region(
        struct vmem_map *map,
        struct vmem_region_ref *ref)
{
    int res;
    int pt_level = map->arch_state.pt_level;

    uint64_t *map_entry = NULL;
    paddr_t map_table = map->arch_state.pt_root;
    paddr_t region_table = ref->region->arch_state.pt_table;

    if(pt_level < ref->region->arch_state.pt_level) {
        eprintk("arch_vmem_map_map_region: invalid map->pt_level < region->pt_level (%d < %d)\n",
                (int)pt_level, (int)ref->region->arch_state.pt_level);
        return -EINVAL;
    }

    while(pt_level > ref->region->arch_state.pt_level) {

        size_t index = pt_level_table_index(map->arch_state.pt_level, ref->virt_addr);
        map_entry = ((uint64_t*)__va(map->arch_state.pt_root)) + index;

        size_t next_table_size;
        uint64_t present_mask;
        uint64_t shared_mask;
        uint64_t addr_mask;

        next_table_size = pt_level_table_size(pt_level-1);
        present_mask = pt_level_present_mask(pt_level);
        res = pt_level_shared_mask(pt_level, &shared_mask);
        if(res) {return res;}
        addr_mask = pt_level_addr_mask(pt_level);

        if(present_mask & *map_entry) {
            if(*map_entry & shared_mask) {
                map_table = addr_mask & *map_entry;
            } else {
                // the map entry points to some other region's page table
                paddr_t shared_table;
                res = page_alloc(ptr_orderof(next_table_size), &shared_table, 0);
                if(res) {
                    return -ENOMEM;
                }

                // Make a copy of the other region's top level table
                map_table = addr_mask & *map_entry;
                memcpy((void*)__va(shared_table), (void*)__va(map_table), next_table_size);

                // Create a shared table entry
                res = create_shared_pt_table_entry(
                        map_entry,
                        pt_level,
                        shared_table);
                if(res) {
                    return res;
                }

                map_table = shared_table;
            }
        } else {
            paddr_t shared_table;
            res = page_alloc(ptr_orderof(next_table_size), &shared_table, 0);
            if(res) {
                return -ENOMEM;
            }
            memset((void*)__va(shared_table), 0, next_table_size);

            // Create a shared table entry
            res = create_shared_pt_table_entry(
                    map_entry,
                    pt_level,
                    shared_table);
            if(res) {
                return res;
            }

            map_table = shared_table;
        }

        pt_level--;
    }

    if(ref->region->arch_state.entry_only) {
        size_t index;
        index = pt_level_table_index(pt_level, ref->virt_addr);

        uint64_t *entry = ((uint64_t*)__va(map_table)) + index;
        size_t present_mask;
        present_mask = pt_level_present_mask(pt_level);

        int can_be_leaf = pt_level_entry_can_be_leaf(pt_level);
        if(!can_be_leaf) {
           eprintk("Tried mapping entry_only region with invalid pt_level (%d)\n", pt_level);
           return -EINVAL;
        }

        if(*entry & present_mask) {
            eprintk("Tried mapping entry_only vmem_region with unexpected overlap!\n");
            return -EINVAL;
        }

        *entry = ref->region->arch_state.pt_entry;
    }
    else {
        res = map_region_tables(
                map_table,
                region_table,
                pt_level,
                ref->virt_addr,
                map,
                ref->region);
        if(res) {
            return res;
        }
    }

    return 0;
}

static int
unmap_region_tables(
        paddr_t map_table,
        paddr_t region_table,
        int table_level,
        vaddr_t vbase)
{
    int res;

    size_t table_size;
    size_t level_below_size;
    size_t entry_region_size;
    size_t num_possible_entries;
    size_t level_below_num_possible_entries;
    size_t entry_must_be_leaf = 0;
    size_t entry_can_be_leaf = 0;
    size_t vindex;

    uint64_t page_size_mask;
    uint64_t present_mask;
    uint64_t next_table_addr_mask;

    switch(table_level) {
        case 1:
            table_size = X64_PT_SIZE;
            level_below_size = 0;
            entry_region_size = X64_PT_ENTRY_REGION_SIZE;
            num_possible_entries = X64_PT_ENTRIES;
            level_below_num_possible_entries = 0;
            vindex = X64_PT_INDEX_OF_ADDR(vbase);
            entry_must_be_leaf = 1;
            entry_can_be_leaf = 1;
            present_mask = X64_PT_LEAF_PRESENT;
            break;
        case 2:
            table_size = X64_PD_SIZE;
            level_below_size = X64_PT_SIZE;
            entry_region_size = X64_PD_ENTRY_REGION_SIZE;
            num_possible_entries = X64_PD_ENTRIES;
            level_below_num_possible_entries = X64_PT_ENTRIES;
            vindex = X64_PD_INDEX_OF_ADDR(vbase);
            page_size_mask = X64_PD_LEAF_PAGE_SIZE;
            entry_can_be_leaf = 1;
            present_mask = X64_PD_LEAF_PRESENT;
            next_table_addr_mask = X64_PD_ENTRY_ADDR_MASK;
            break;
        case 3:
            table_size = X64_PDPT_SIZE;
            level_below_size = X64_PD_SIZE;
            entry_region_size = X64_PDPT_ENTRY_REGION_SIZE;
            num_possible_entries = X64_PDPT_ENTRIES;
            level_below_num_possible_entries = X64_PD_ENTRIES;
            vindex = X64_PDPT_INDEX_OF_ADDR(vbase);
            page_size_mask = X64_PDPT_LEAF_PAGE_SIZE;
            entry_can_be_leaf = 1;
            present_mask = X64_PDPT_LEAF_PRESENT;
            next_table_addr_mask = X64_PDPT_ENTRY_ADDR_MASK;
            break;
        case 4:
            table_size = X64_PML4_SIZE;
            level_below_size = X64_PDPT_SIZE;
            entry_region_size = X64_PML4_ENTRY_REGION_SIZE;
            num_possible_entries = X64_PML4_ENTRIES;
            level_below_num_possible_entries = X64_PDPT_ENTRIES;
            vindex = X64_PML4_INDEX_OF_ADDR(vbase);
            present_mask = X64_PML4_ENTRY_PRESENT;
            next_table_addr_mask = X64_PML4_ENTRY_ADDR_MASK;
            break;
        default:
            eprintk("unmap_region_tables: invalid table_level (%d)\n", table_level);
            return -EINVAL;
    }

    for(size_t vi = vindex; vi < num_possible_entries; vi++) {
        uint64_t *map_entry = &((uint64_t*)__va(map_table))[vi];
        uint64_t *region_entry = &((uint64_t*)__va(region_table))[vi-vindex];

        if(!(*region_entry & present_mask)) {
            // Region isn't present, so this is the end of the region
            break;
        }

        int map_is_leaf = entry_must_be_leaf ? 1 :
                          entry_can_be_leaf ? *map_entry & page_size_mask : 0;
        int region_is_leaf = entry_must_be_leaf ? 1 :
                             entry_can_be_leaf ? *region_entry & page_size_mask : 0;

        if(map_is_leaf != region_is_leaf) {
            eprintk("unmap_region_tables: map_is_leaf != region_is_leaf\n");
            return -EINVAL;
        }
        else if(map_is_leaf /* && region_is_leaf */) {
            // Zero out the entry in the map
            *map_entry = 0;
        } else {
            // They are both tables
            paddr_t map_next_addr = *map_entry & next_table_addr_mask;
            paddr_t region_next_addr = *region_entry & next_table_addr_mask;
            if(map_next_addr == region_next_addr) {
                // The region owns this page
                *map_entry = 0;
            } else {
                // This is a shared page
                res = unmap_region_tables(
                        map_next_addr,
                        region_next_addr,
                        table_level-1,
                        vbase + (entry_region_size * (vi-vindex)));
                if(res) {
                    eprintk("Failed to unmap vmem region subtable (Possible Physical Memory Leak)! (err=%s)\n", errnostr(res));
                    continue;
                }
                // Check if the shared table is now empty
                int can_free_table = 1;
                for(size_t below = 0; below < level_below_num_possible_entries; below++) {
                    uint64_t *below_entry = ((uint64_t*)__va(map_next_addr)) + below;
                    if(*below_entry != 0) {
                        can_free_table = 0;
                        break;
                    }
                }
                if(can_free_table) {
                    // Free the shared table if it's now empty
                    page_free(ptr_orderof(level_below_size), map_next_addr);
                    *map_entry = 0;
                }
            }
        }
    }

    return 0;
}


int
arch_vmem_map_unmap_region(
        struct vmem_map *map,
        struct vmem_region_ref *ref)
{
    int res;
    int pt_level = map->arch_state.pt_level;

    uint64_t *map_entry = NULL;
    paddr_t map_table = map->arch_state.pt_root;
    paddr_t region_table = ref->region->arch_state.pt_table;

    if(pt_level < ref->region->arch_state.pt_level) {
        eprintk("arch_vmem_map_unmap_region: map->pt_level < region->pt_level (%d < %d)\n",
                pt_level, ref->region->arch_state.pt_level);
        return -EINVAL;
    }

    while(pt_level > ref->region->arch_state.pt_level) {
        size_t index = pt_level_table_index(map->arch_state.pt_level, ref->virt_addr);
        map_entry = ((uint64_t*)__va(map_table)) + index;

        uint64_t addr_mask = pt_level_addr_mask(pt_level);
        uint64_t present_mask = pt_level_present_mask(pt_level);

        if(!(*map_entry & present_mask)) {
            eprintk("arch_vmem_map_unmap_region: found not-present page table in region!\n");
            return -EINVAL;
        }
        map_table = *map_entry & addr_mask;
        pt_level--;
    }

    if(ref->region->arch_state.entry_only) {
        size_t index = pt_level_table_index(pt_level, ref->virt_addr);
        uint64_t *entry = ((uint64_t*)__va(map_table)) + index;
        switch(pt_level) {
            case 1: 
                if(!(*entry & X64_PT_LEAF_PRESENT)) 
                {
                    eprintk("Found not-present page when unmapping entry_only vmem_region!\n");
                    return -EINVAL;
                }
                *entry = 0;
                break;
            case 2:
                if(!(*entry & X64_PD_LEAF_PRESENT) ||
                   !(*entry & X64_PD_ENTRY_PAGE_SIZE)) 
                {
                    eprintk("Found not-present or non-leaf page when unmapping entry_only vmem_region!\n");
                    return -EINVAL;
                }
                *entry = 0;
                break;
            case 3:
                if(!(*entry & X64_PDPT_LEAF_PRESENT) ||
                   !(*entry & X64_PDPT_ENTRY_PAGE_SIZE)) 
                {
                    eprintk("Found not-present or non-leaf page when unmapping entry_only vmem_region!\n");
                    return -EINVAL;
                }
                *entry = 0;
                break;
            default:
                eprintk("Invalid pt_level for leaf page when unmapping vmem_region! (level=%d)\n", pt_level);
                return -EINVAL;
        }
    } else {
        res = unmap_region_tables(
                map_table,
                region_table,
                pt_level,
                ref->virt_addr);
        if(res) {
            return res;
        }
    }

    if(pt_level != map->arch_state.pt_level) {
        // TODO check if the top level directory is now empty,
        // and free completely "not-present" intermediate tables
        dprintk("WARNING: Not checking for pointless intermediate"
                " page tables on region unmapping."
                " (could be wasting memory)\n");
    }

    return 0;
}

int
arch_vmem_paged_region_map(
        struct vmem_region *region,
        size_t offset,
        paddr_t phys_addr,
        size_t size,
        unsigned long flags)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(region));
    DEBUG_ASSERT(KERNEL_ADDR(__va(phys_addr)));

    if(offset % X64_PT_ENTRY_REGION_SIZE ||
       size % X64_PT_ENTRY_REGION_SIZE)
    {
        eprintk("Cannot map paged area offsets: [%p - %p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(offset), (uintptr_t)(offset + size));
        return -EINVAL;
    }

    if(phys_addr % X64_PT_ENTRY_REGION_SIZE) 
    {
        eprintk("Cannot map paged area to physical address (%p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(phys_addr));
        return -EINVAL;
    }

    while(size > 0)
    {
        int max_entry_level = region->arch_state.pt_level-1;

        size_t entries_per_table;
        size_t page_size;
        int entry_level;
        if(size >= X64_PDPT_ENTRY_REGION_SIZE
           && (phys_addr % X64_PDPT_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 3)
        {
            page_size = X64_PDPT_ENTRY_REGION_SIZE;
            entries_per_table = X64_PDPT_ENTRIES;
            entry_level = 3;
        }
        else if(size >= X64_PD_ENTRY_REGION_SIZE
           && (phys_addr % X64_PD_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 2)
        {
            page_size = X64_PD_ENTRY_REGION_SIZE;
            entries_per_table = X64_PD_ENTRIES;
            entry_level = 2;
        }
        else if(size >= X64_PT_ENTRY_REGION_SIZE
           && (phys_addr % X64_PT_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 1)
        {
            page_size = X64_PT_ENTRY_REGION_SIZE;
            entries_per_table = X64_PT_ENTRIES;
            entry_level = 1;
        } else {
            // We failed a check we should have already passed,
            // something screw-y is going on with our memory (PANIC!)
            panic("End of paged region mapping is misaligned (even though we passed this check at the beginning of \"arch_vmem_paged_region_map\"!");
        }

        // Drill the mapping
        
        paddr_t cur_table = region->arch_state.pt_table;
        int cur_level = region->arch_state.pt_level;

        x64_verify_page_table(
                region->arch_state.pt_table,
                region->arch_state.pt_level);

        do {
            size_t cur_region_size = pt_level_entry_region_size(cur_level);
            size_t cur_entries_per_table = pt_level_num_table_entries(cur_level);
            size_t cur_index = (offset / cur_region_size) % cur_entries_per_table;
            uint64_t *cur_entry = ((uint64_t*)__va(cur_table)) + cur_index;

            x64_verify_page_table(
                cur_table,
                cur_level);

            uint64_t present_mask = pt_level_present_mask(cur_level);

            if(present_mask & *cur_entry) {
                // This must be a page table
                DEBUG_ASSERT(!pt_level_entry_is_leaf(cur_level, *cur_entry));

                uint64_t addr_mask = pt_level_addr_mask(cur_level);
                cur_table = *cur_entry & addr_mask;

                DEBUG_ASSERT_MSG(KERNEL_ADDR((void*)__va(cur_table)),
                        "table paddr=%p, vaddr=%p, cur_entry=%p",
                        (void*)cur_table,
                        (void*)__va(cur_table),
                        (uint64_t)*cur_entry);

                cur_level--;
            }
            else {
                // The entry isn't present
                paddr_t subtable;
                res = create_empty_pt_table(
                        &subtable,
                        cur_level-1);
                if(res) {
                    return res;
                }

                DEBUG_ASSERT(KERNEL_ADDR((void*)__va(subtable)));

                res = create_permissive_pt_table_entry(
                        cur_entry,
                        cur_level,
                        subtable);
                if(res) {
                    return res;
                }

                cur_table = subtable;
                cur_level--;
            }
        } while(cur_level != entry_level);

        // We should be on the correct level
        size_t index = (offset / page_size) % entries_per_table;
        uint64_t *entry = ((uint64_t*)__va(cur_table)) + index;

        res = create_pt_leaf_entry(entry, entry_level, phys_addr, flags);
        if(res) {
            return res;
        }

        offset += page_size;
        phys_addr += page_size;
        size -= page_size;
    }

    return 0;
}

int
arch_vmem_paged_region_unmap(
        struct vmem_region *region,
        size_t offset,
        size_t size) 
{
    int res;

    if(offset % X64_PT_ENTRY_REGION_SIZE ||
       size % X64_PT_ENTRY_REGION_SIZE)
    {
        eprintk("Cannot map paged area offsets: [%p - %p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(offset), (uintptr_t)(offset + size));
        return -EINVAL;
    }

    while(size > 0)
    {
        int max_entry_level = region->arch_state.pt_level-1;

        size_t entries_per_table;
        size_t page_size;
        int entry_level;
        if(size >= X64_PDPT_ENTRY_REGION_SIZE
           && (offset % X64_PDPT_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 3)
        {
            page_size = X64_PDPT_ENTRY_REGION_SIZE;
            entries_per_table = X64_PDPT_ENTRIES;
            entry_level = 3;
        }
        else if(size >= X64_PD_ENTRY_REGION_SIZE
           && (offset % X64_PD_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 2)
        {
            page_size = X64_PD_ENTRY_REGION_SIZE;
            entries_per_table = X64_PD_ENTRIES;
            entry_level = 2;
        }
        else if(size >= X64_PT_ENTRY_REGION_SIZE
           && (offset % X64_PT_ENTRY_REGION_SIZE == 0)
           && max_entry_level >= 1)
        {
            page_size = X64_PT_ENTRY_REGION_SIZE;
            entries_per_table = X64_PT_ENTRIES;
            entry_level = 1;
        } else {
            // We failed a check we should have already passed,
            // something screw-y is going on with our memory (PANIC!)
            panic("End of paged region mapping is misaligned (even though we passed this check at the beginning of \"arch_vmem_paged_region_map\"!");
        }

        // Drill the mapping
        
        paddr_t cur_table = region->arch_state.pt_table;
        int cur_level = region->arch_state.pt_level;

        do {
            size_t cur_region_size = pt_level_entry_region_size(cur_level);
            size_t cur_entries_per_table = pt_level_num_table_entries(cur_level);
            size_t cur_index = (offset / cur_region_size) % cur_entries_per_table;
            uint64_t *cur_entry = ((uint64_t*)__va(cur_table)) + cur_index;

            DEBUG_ASSERT(KERNEL_ADDR(cur_entry));

            uint64_t present_mask = pt_level_present_mask(cur_level);

            if(present_mask & *cur_entry) {
                // This must be a page table (TODO check this in an assertion)
                uint64_t addr_mask = pt_level_addr_mask(cur_level);
                cur_table = *cur_entry & addr_mask;
                cur_level--;
            }
            else {
                // The entry isn't present
                paddr_t subtable;
                res = create_empty_pt_table(
                        &subtable,
                        cur_level-1);
                if(res) {
                    return res;
                }

                DEBUG_ASSERT(KERNEL_ADDR((void*)__va(subtable)));

                res = create_permissive_pt_table_entry(
                        cur_entry,
                        cur_level,
                        subtable);
                if(res) {
                    return res;
                }

                cur_table = subtable;
                cur_level--;
            }
        } while(cur_level != entry_level);

        // We should be on the correct level
        size_t index = (offset / page_size) % entries_per_table;
        uint64_t *entry = ((uint64_t*)__va(cur_table)) + index;

        // Unmap the entry fully
        *entry = 0;

        offset += page_size;
        size -= page_size;
    }

    return 0;
}

int
arch_vmem_map_activate(
        struct vmem_map *map)
{
    DEBUG_ASSERT(KERNEL_ADDR(map));
    DEBUG_ASSERT(ptr_orderof(map->arch_state.pt_root) >= 12);

    write_cr3(map->arch_state.pt_root);
    return 0;
}

static int
dump_page_table(printk_f *printer, paddr_t table_phys_addr, int level, vaddr_t virt_base)
{
    int res = 0;

    if(level > 5 || level <= 0) {
        (*printer)("dump_page_table somehow reached invalid table level (%d)\n", level);
        return -EINVAL;
    }

    int num_tabs = 5 - level;
#define PUT_TABS()\
    for(int __tab = 0; __tab < num_tabs; __tab++) {\
        (*printer)("  ");\
    }

    size_t entry_region_size = pt_level_entry_region_size(level);
    size_t num_entries = pt_level_num_table_entries(level);
    uint64_t addr_mask = pt_level_addr_mask(level);
    uint64_t present_mask = pt_level_present_mask(level);

    uint64_t *table = (void*)__va(table_phys_addr);

    int leaf_pending = 0;

    paddr_t pending_next_paddr;
    paddr_t pending_paddr;
    vaddr_t pending_vaddr;
    size_t pending_size;
    uint64_t pending_flags;

#define DUMP_PENDING_LEAF()\
    do {\
        PUT_TABS();\
        (*printer)("%p -> %p [size=0x%llx]\n", pending_vaddr, pending_paddr, (ull_t)pending_size);\
    } while(0)

    for(size_t entry_index = 0; entry_index < num_entries; entry_index++)
    {
        uint64_t entry = table[entry_index];
        paddr_t addr = entry & addr_mask;
        uint64_t flags = entry & ~addr_mask;

        if((entry & present_mask) == 0) {
            // Not Present, continue.
            virt_base += entry_region_size;
            continue;
        }
        
        int is_leaf = pt_level_entry_is_leaf(level, entry);

        if(leaf_pending) {
            if(!is_leaf) {
                // Dump the pending leaf because we are going down a level
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            } else if(flags != pending_flags || addr != pending_next_paddr) {
                // Dump the pending leaf because some flag or address changed
                DUMP_PENDING_LEAF();
                leaf_pending = 1;
                pending_paddr = addr;
                pending_next_paddr = addr + entry_region_size;
                pending_vaddr = virt_base;
                pending_size = entry_region_size;
                pending_flags = flags;
            } else {
                // Don't dump the leaf, just extend it
                leaf_pending = 1;
                pending_size += entry_region_size;
                pending_next_paddr += entry_region_size;
            }
        } else if(is_leaf) {
            leaf_pending = 1;
            pending_paddr = addr;
            pending_next_paddr = addr + entry_region_size;
            pending_vaddr = virt_base;
            pending_size = entry_region_size;
            pending_flags = flags;
        }

        if(!is_leaf) {
            res = dump_page_table(printer, addr, level - 1, virt_base);
            if(res) {return res;}
        }

        virt_base += entry_region_size;
    }

    if(leaf_pending) {
        leaf_pending = 0;
        DUMP_PENDING_LEAF();
    }

#undef PUT_TABS
#undef DUMP_PENDING_LEAF

    return res;
}

static void
tlb_shootdown_xcall(void *with_cr3) {

    // Disable IRQs to make absolutely sure we can't change the
    // value of cr3 by accident
    int irq_flags = disable_save_irqs();
    uint64_t cr3 = read_cr3();
    if(cr3 == (uint64_t)with_cr3) {
        write_cr3(cr3);
    }
    enable_restore_irqs(irq_flags);
}

int
arch_vmem_map_flush(struct vmem_map *map)
{
    if(map->active_on <= 0) {
        return 0;
    }

    if((map->active_on == 1)
      && map == vmem_map_get_current()) {
        write_cr3(read_cr3());
        return 0;
    }

    int res = xcall_broadcast(tlb_shootdown_xcall, (void*)map->arch_state.pt_root);
    if(res) {
        return res;
    }

    return 0;
}

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map)
{
    paddr_t root = map->arch_state.pt_root;
    (*printer)("--- x64 Virtual Memory Mapping (Root Level = %d) ---\n", map->arch_state.pt_level);
    int res = dump_page_table(printer, map->arch_state.pt_root, map->arch_state.pt_level, 0x0);
    if(res) {
        (*printer)("[[[ An Error Occurred When Printing Virtual Memory Mapping (err=%s)\n",
                errnostr(res));
    }
    (*printer)("----------------------------------------------------\n");
}

