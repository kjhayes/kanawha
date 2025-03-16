
#include <arch/riscv64/mmu.h>
#include <arch/riscv64/csr.h>
#include <kanawha/vmem.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/xcall.h>
#include <kanawha/irq.h>
#include <kanawha/init.h>

#ifdef CONFIG_RISCV64_SV57
#define MAX_LEVEL 4
#else
#ifdef CONFIG_RISCV64_SV48
#define MAX_LEVEL 3
#else
#ifdef CONFIG_RISCV64_SV39
#define MAX_LEVEL 2
#else
#error "One of CONFIG_RISCV64_SV39, CONFIG_RISCV64_SV48, or CONFIG_RISCV64_SV57 must be defined!"
#endif
#endif
#endif

static inline size_t
sv_level_page_size(int level)
{
    DEBUG_ASSERT(level <= MAX_LEVEL);
    switch(level) {
        case 0: return RISCV64_SV_PAGE_SIZE_LEVEL_0;
        case 1: return RISCV64_SV_PAGE_SIZE_LEVEL_1;
        case 2: return RISCV64_SV_PAGE_SIZE_LEVEL_2;
#ifdef CONFIG_RISCV64_SV48
        case 3: return RISCV64_SV_PAGE_SIZE_LEVEL_3;
#ifdef CONFIG_RISCV64_SV57
        case 4: return RISCV64_SV_PAGE_SIZE_LEVEL_4;
#endif
#endif
        default:
            panic("sv_level_pagesize was given an invalid level=%d\n", level);
    }
}

static inline order_t
sv_level_page_order(int level)
{
    DEBUG_ASSERT(level <= MAX_LEVEL);
    switch(level) {
        case 0: return RISCV64_SV_PAGE_ORDER_LEVEL_0;
        case 1: return RISCV64_SV_PAGE_ORDER_LEVEL_1;
        case 2: return RISCV64_SV_PAGE_ORDER_LEVEL_2;
#ifdef CONFIG_RISCV64_SV48
        case 3: return RISCV64_SV_PAGE_ORDER_LEVEL_3;
#ifdef CONFIG_RISCV64_SV57
        case 4: return RISCV64_SV_PAGE_ORDER_LEVEL_4;
#endif
#endif
        default:
            panic("sv_level_order was given an invalid level=%d\n", level);
    }
}

static inline size_t
sv_level_index_of_addr(int level, void *addr)
{
    DEBUG_ASSERT(level <= MAX_LEVEL);
    size_t index;
    switch(level) {
        case 0: index = RISCV64_SV_LEVEL_0_INDEX_OF_ADDR((uintptr_t)addr); break;
        case 1: index = RISCV64_SV_LEVEL_1_INDEX_OF_ADDR((uintptr_t)addr); break;
        case 2: index = RISCV64_SV_LEVEL_2_INDEX_OF_ADDR((uintptr_t)addr); break;
#ifdef CONFIG_RISCV64_SV48
        case 3: index = RISCV64_SV_LEVEL_3_INDEX_OF_ADDR((uintptr_t)addr); break;
#ifdef CONFIG_RISCV64_SV57
        case 4: index = RISCV64_SV_LEVEL_4_INDEX_OF_ADDR((uintptr_t)addr); break;
#endif
#endif
        default:
            panic("sv_level_index_of_addr was given an invalid level=%d\n", level);
    }
    DEBUG_ASSERT(index < RISCV64_SV_ENTRIES_PER_LEVEL);
    return index;
}

static inline void __phys *
sv_pointer_from_entry(uint64_t entry)
{
    return (void __phys *)((entry << 2) & ~0xFFF);
}

static void
riscv64_verify_page_table(
        struct riscv64_sv_page_table __phys *phys_table,
        int level)
{
    if(level > MAX_LEVEL || level < 0) {
        panic("Found invalid level (%d) in page table!\n", level);
    }
    if(level < 0) {
    }
    struct riscv64_sv_page_table *table = __va(phys_table);
    for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL; i++) {
        uint64_t *entry = &table->entries[i];
        if(*entry & RISCV64_SV_VALID) {
            void __phys *addr = sv_pointer_from_entry(*entry);
            if(RISCV64_SV_ENTRY_IS_LEAF(*entry)) {
                size_t page_size = sv_level_page_size(level);
                if((uintptr_t)addr % page_size) {
                    panic("Unaligned Physical Page in Page Table Level %d\n", level);
                }
            } else {
                riscv64_verify_page_table(
                        addr,
                        level-1);
            }
        } else {
            // We should only have fully NULL entries which are not valid
            if(*entry) {
                panic("Non-NULL invalid page table entry found!\n");
            }
        }
    }
}

static void
riscv64_dump_page_table(
        printk_f *printer,
        struct riscv64_sv_page_table __phys *phys_table,
        void *vbase,
        int level)
{
    if(level < 0) {
        eprintk("riscv64_dump_page_table reached an invalid level!\n");
        return;
    }

#define TAB() \
    do {\
        for(int __i = 0; __i < (MAX_LEVEL-level); __i++) {\
            (*printer)("\t");\
        }\
    } while(0)

    int leaf_pending = 0;
    void __phys *pending_next_paddr;
    void __phys *pending_paddr;
    void *pending_vaddr;
    size_t pending_size;

#define DUMP_PENDING_LEAF()\
    do {\
        TAB();\
        if((uintptr_t)pending_vaddr & (1ULL<<(VADDR_BITS-1))) {\
            pending_vaddr = (void*)((uintptr_t)pending_vaddr | ((~(uintptr_t)0)<<VADDR_BITS));\
        }\
        (*printer)("%p -> %p [size=0x%llx]\n",\
                pending_vaddr,\
                pending_paddr,\
                pending_size);\
    } while(0)

#if defined(CONFIG_RISCV64_SV57)
#define VADDR_BITS 57
#elif defined(CONFIG_RISCV64_SV48)
#define VADDR_BITS 48
#elif defined(CONFIG_RISCV64_SV39)
#define VADDR_BITS 39
#endif

    size_t page_size = sv_level_page_size(level);
    struct riscv64_sv_page_table *table = __va(phys_table);

    for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL; i++)
    {
        uint64_t *entry = &table->entries[i];
        if(!(*entry & RISCV64_SV_VALID)) {
            vbase += page_size;
            if(leaf_pending) {
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            }
            continue;
        }

        void __phys *cur_paddr = sv_pointer_from_entry(*entry);

        int is_leaf = RISCV64_SV_ENTRY_IS_LEAF(*entry);

        if(leaf_pending) {
            if(!is_leaf) {
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            } else if(cur_paddr != pending_next_paddr) {
                DUMP_PENDING_LEAF();
                leaf_pending = 1;
                pending_paddr = cur_paddr;
                pending_next_paddr = cur_paddr + page_size;
                pending_vaddr = vbase;
                pending_size = page_size;
            } else {
                leaf_pending = 1;
                pending_size += page_size;
                pending_next_paddr += page_size;
            }
        } else if(is_leaf) {
            leaf_pending = 1;
            pending_paddr = cur_paddr;
            pending_next_paddr = cur_paddr + page_size;
            pending_vaddr = vbase;
            pending_size = page_size;
        }

        if(!is_leaf) {
            riscv64_dump_page_table(
                    printer,
                    cur_paddr,
                    vbase,
                    level-1);
        }

        vbase += page_size;
    }

    if(leaf_pending) {
        leaf_pending = 0;
        DUMP_PENDING_LEAF();
    }

#undef TAB
#undef DUMP_PENDING_LEAF
}

int arch_vmem_map_init(struct vmem_map *generic_map)
{
    int res;

    struct arch_vmem_map *map = &generic_map->arch_state;
    map->root_level = MAX_LEVEL;

    // Allocate the root page of the table
    res = page_alloc(
            RISCV64_SV_TABLE_ORDER,
            (void __phys **)&map->root_table,
            0);
    if(res) {
        eprintk("Failed to allocate vmem_map root page table!\n");
        return -ENOMEM;
    }

    struct riscv64_sv_page_table *pt = __va(map->root_table);
    memset(pt, 0, sizeof(struct riscv64_sv_page_table));

    return 0;
}

static int
free_sv_page_tables(
        struct riscv64_sv_page_table __phys *phys_table,
        int level)
{
    int res;
    if(level > 0) {
        struct riscv64_sv_page_table *table = __va(phys_table);
        for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL; i++) {
            uint64_t *entry = &table->entries[i];
            if(!(*entry & RISCV64_SV_VALID)) {
                continue;
            }
            if(!RISCV64_SV_ENTRY_IS_LEAF(*entry)) {
                struct riscv64_sv_page_table __phys *subtable =
                    sv_pointer_from_entry(*entry);
                *entry = 0;
                res = free_sv_page_tables(subtable, level-1);
                if(res) {
                    wprintk("Failed to free subtree of page table (%s) Leaking Memory!\n",
                            errnostr(res));
                }
            }
        }
    }
    return page_free(RISCV64_SV_TABLE_ORDER, phys_table);
}

int arch_vmem_map_deinit(struct vmem_map *map)
{
    int res;
    // Every region should have been unmapped already
    res = free_sv_page_tables(map->arch_state.root_table, map->arch_state.root_level);
    if(res) {
        return res;
    }
    return 0;
}

static int
create_empty_sv_table(struct riscv64_sv_page_table __phys **table_ptr)
{
    int res;
    res = page_alloc(
            RISCV64_SV_TABLE_ORDER,
            (void __phys **)table_ptr,
            0);
    if(res) {
        return res;
    }

    struct riscv64_sv_page_table *table = __va(*table_ptr);
    memset(table, 0, sizeof(struct riscv64_sv_page_table));

    return 0;
}

static int
destroy_empty_sv_table(struct riscv64_sv_page_table __phys *table)
{
    int res;
    res = page_free(RISCV64_SV_TABLE_ORDER, table);
    if(res) {
        return res;
    }
    return res;
}

static int
create_sv_table_entry(
        uint64_t *entry,
        int level,
        struct riscv64_sv_page_table __phys *subtable)
{
    uint64_t value = (((uintptr_t)subtable) >> 2) & ~0x3FF;

    value |= RISCV64_SV_VALID;

    if(RISCV64_SV_ENTRY_IS_LEAF(value)) {
        *entry = 0;
        return -EINVAL;
    }

    *entry = value;
    return 0;

    return 0;
}
static int
create_sv_shared_table_entry(
        uint64_t *entry,
        int level,
        struct riscv64_sv_page_table __phys *subtable)
{
    uint64_t value = (((uintptr_t)subtable) >> 2) & ~0x3FF;

    value |= RISCV64_SV_VALID;
    value |= RISCV64_SV_VMEM_SHARED_MAP;

    if(RISCV64_SV_ENTRY_IS_LEAF(value)) {
        *entry = 0;
        return -EINVAL;
    }

    *entry = value;
    return 0;

    return 0;
}

static int
create_sv_leaf_entry(
        uint64_t *entry,
        int level,
        void __phys *phys_addr,
        unsigned long flags)
{
    uint64_t value = (((uintptr_t)phys_addr) >> 2) & ~0x3FF;

    value |= RISCV64_SV_VALID;
    value |= (flags & VMEM_REGION_READ)  ? RISCV64_SV_READ  : 0;
    value |= (flags & VMEM_REGION_WRITE) ? RISCV64_SV_WRITE : 0;
    value |= (flags & VMEM_REGION_EXEC)  ? RISCV64_SV_EXEC  : 0;
    value |= (flags & VMEM_REGION_USER)  ? RISCV64_SV_USER  : 0;

    if(!RISCV64_SV_ENTRY_IS_LEAF(value)) {
        *entry = 0;
        panic("Failed to create leaf page table entry!\n");
    }

    *entry = value;
    return 0;
}

static int
create_direct_sv_table(
        struct riscv64_sv_page_table __phys **table_ptr,
        int level,
        void __phys *base,
        size_t size,
        unsigned long flags)
{
    int res;
    res = create_empty_sv_table(table_ptr);
    if(res) {
        return res;
    }

    DEBUG_ASSERT(ptr_orderof(base) >= RISCV64_SV_PAGE_ORDER_LEVEL_0);

    struct riscv64_sv_page_table *table = __va(*table_ptr);

    size_t page_size = sv_level_page_size(level);

    for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL; i++) {
        uint64_t *entry = &table->entries[i];
        if(size >= page_size) {
            res = create_sv_leaf_entry(
                    entry,
                    level,
                    base,
                    flags);
            if(res) {
                destroy_empty_sv_table(*table_ptr);
                return res;
            }
            size -= page_size;
            base += page_size;
        } else {
            if(size != 0) {
                struct riscv64_sv_page_table __phys *subtable;
                res = create_direct_sv_table(
                        &subtable,
                        level-1,
                        base,
                        size,
                        flags);
                if(res) {
                    destroy_empty_sv_table(*table_ptr);
                    return res;
                }
                res = create_sv_table_entry(
                        entry,
                        level,
                        subtable);
                if(res) {
                    // TODO (We currently leak any children of the subtable
                    wprintk("Hit Possible Memory Leak Condition\n");
                    destroy_empty_sv_table(subtable);
                    destroy_empty_sv_table(*table_ptr);
                    return res;
                }
            }
            break;
        }
    }

    riscv64_verify_page_table(*table_ptr, level);
    return 0;
}

static int
create_paged_sv_table(
        struct riscv64_sv_page_table __phys **table_ptr,
        int level,
        size_t size)
{
    int res;

    if(level == 0) {
        // We cannot create a paged table at the lowest level
        return -EINVAL;
    }
   
    // If we fail we don't free any of our tables (TODO)
    res = create_empty_sv_table(table_ptr);
    if(res) {
        return res;
    }
    struct riscv64_sv_page_table *table = __va(*table_ptr);

    size_t page_size = sv_level_page_size(level);
    size_t full_pages = size / page_size;

    for(size_t i = 0; i < full_pages; i++) {
        struct riscv64_sv_page_table __phys *subtable;
        res = create_empty_sv_table(&subtable);
        if(res) {
            return res;
        }

        uint64_t *entry = &table->entries[i];
        res = create_sv_table_entry(
                entry,
                level,
                subtable);
        if(res) {
            return res;
        }
    }

    size_t remaining_size = size - (full_pages * page_size);
    if(remaining_size > 0) {
        struct riscv64_sv_page_table __phys *subtable;
        res = create_paged_sv_table(
                &subtable,
                level-1,
                remaining_size);
        if(res) {
            return res;
        }
        uint64_t *entry = &table->entries[full_pages];
        res = create_sv_table_entry(
                entry,
                level,
                subtable);
        if(res) {
            return res;
        }
    }

    riscv64_verify_page_table(*table_ptr, level);
    return 0;
}

static int
arch_vmem_region_init_direct(struct vmem_region *region)
{
    int res;
    uintptr_t phys_base = (uintptr_t)region->direct.phys_base;
    uintptr_t phys_end = (uintptr_t)region->direct.phys_base + (uintptr_t)region->size;

    if(phys_base % RISCV64_SV_PAGE_SIZE_LEVEL_0) {
        eprintk("Tried to initialize a direct region with physical base unaligned from the smallest page size!\n");
        return -EINVAL;
    }
    if(region->size % RISCV64_SV_PAGE_SIZE_LEVEL_0) {
        eprintk("Tried to initialize direct region with size that isn't a multiple of the minimum page size!\n");
        return -EINVAL;
    }

    if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_1) {
        region->arch_state.root_level = 0; // We can fit inside a single level 0 table
    }
    else if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_2) {
        region->arch_state.root_level = 1; // We can fit inside a single level 1 table
    }
#ifdef CONFIG_RISCV64_SV48
    else if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_3) {
        region->arch_state.root_level = 2; // We can fit inside a single level 2 table
    }
#ifdef CONFIG_RISCV64_SV57
    else if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_4) {
        region->arch_state.root_level = 3; // We can fit inside a single level 3 table
    }
#endif
#endif
    else {
        eprintk("arch_vmem_region_init_direct: region of size = 0x%lx is too large!\n",
                (uintptr_t)region->size);
        return -EINVAL;
    }

    res = create_direct_sv_table(
            &region->arch_state.root_table,
            region->arch_state.root_level,
            (void __phys *)phys_base,
            region->size,
            region->direct.flags);
    if(res) {
        eprintk("arch_vmem_region_init_direct Failed with err=%s\n",
                errnostr(res));
        return res;
    }

    return 0;
}

static int
arch_vmem_region_init_paged(struct vmem_region *region) 
{
    int res;

    if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_2) {
        region->arch_state.root_level = 1; // We can fit inside a single level 1 table
    }
#ifdef CONFIG_RISCV64_SV48
    else if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_3) {
        region->arch_state.root_level = 2; // We can fit inside a single level 2 table
    }
#ifdef CONFIG_RISCV64_SV57
    else if(region->size < RISCV64_SV_PAGE_SIZE_LEVEL_4) {
        region->arch_state.root_level = 3; // We can fit inside a single level 3 table
    }
#endif
#endif
    else {
        return -EINVAL;
    }

    res = create_paged_sv_table(
            &region->arch_state.root_table,
            region->arch_state.root_level,
            region->size);
    if(res) {
        return res;
    }

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

int arch_vmem_region_deinit(struct vmem_region *region)
{
    int res;
    res = free_sv_page_tables(
            region->arch_state.root_table,
            region->arch_state.root_level);
    if(res) {
        return res;
    }
    return 0;
}

order_t
arch_vmem_region_alignment(
        struct vmem_region *region)
{
    int root_level = region->arch_state.root_level;
    order_t order = sv_level_page_order(root_level);
    return order;
}

static int
sv_map_region_tables(
    struct riscv64_sv_page_table __phys * phys_map_table,
    struct riscv64_sv_page_table __phys * phys_region_table,
    int level,
    void * vbase,
    struct vmem_map *map,
    struct vmem_region *region)
{
    int res;

    struct riscv64_sv_page_table *map_table = __va(phys_map_table);
    struct riscv64_sv_page_table *region_table = __va(phys_region_table);

    size_t virtual_index = sv_level_index_of_addr(level, vbase);

    size_t max_num_entries_in_map = RISCV64_SV_ENTRIES_PER_LEVEL - virtual_index;
    if(region_table->entries[max_num_entries_in_map-1] & RISCV64_SV_VALID) {
        // We cannot map this virtual address
        eprintk("Cannot map vmem region to given virtual address!\n");
        return -EINVAL;
    }

    for(size_t vi = virtual_index; vi < RISCV64_SV_ENTRIES_PER_LEVEL; vi++) {
        uint64_t *map_entry = &map_table->entries[vi];
        uint64_t *region_entry = &region_table->entries[vi-virtual_index];

        if(!(*region_entry & RISCV64_SV_VALID)) {
            // This is the end of the region
            dprintk("sv_map_region_tables: Hit end of region at region index = 0x%lx\n",
                    vi-virtual_index);
            return 0;
        }

        if(!(*map_entry & RISCV64_SV_VALID)) {
            // Map in the region directly
            *map_entry = *region_entry;
            dprintk("sv_map_region_tables: mapping directly at index = 0x%lx\n",
                    vi);
            continue;
        }

        if(RISCV64_SV_ENTRY_IS_LEAF(*map_entry)
         ||RISCV64_SV_ENTRY_IS_LEAF(*region_entry)) {
            // This should not be possible (our regions overlap)
            panic("Unexpected vmem region overlap when mapping region tables!\n");
            // This return should not be hit
            return -EINVAL;
        }

        struct riscv64_sv_page_table __phys *
            region_next_table = sv_pointer_from_entry(*region_entry);
        struct riscv64_sv_page_table __phys *
            map_next_table = sv_pointer_from_entry(*map_entry);

        if(!(*map_entry & RISCV64_SV_VMEM_SHARED_MAP)) {
            // The next map table is not shared
            struct riscv64_sv_page_table __phys *phys_shared_table;
            res = create_empty_sv_table(&phys_shared_table);
            if(res) {
                return -ENOMEM;
            }
            struct riscv64_sv_page_table *shared_table = __va(phys_shared_table);

            // Copy the other region's table
            memcpy(shared_table, __va(map_next_table), sizeof(struct riscv64_sv_page_table));

            res = create_sv_shared_table_entry(
                map_entry,
                level,
                phys_shared_table);
            if(res) {
                return res;
            }
        }

        map_next_table = sv_pointer_from_entry(*map_entry);

        res = sv_map_region_tables(
                map_next_table,
                region_next_table,
                level-1,
                vbase + (sv_level_page_size(level) * (vi-virtual_index)),
                map,
                region);
        if(res) {
            return res;
        }
    }

    return 0;
}

static int
sv_unmap_region_tables(
    struct riscv64_sv_page_table __phys * phys_map_table,
    struct riscv64_sv_page_table __phys * phys_region_table,
    int level,
    void * vbase,
    struct vmem_map *map,
    struct vmem_region *region)
{
    int res;

    struct riscv64_sv_page_table *map_table = __va(phys_map_table);
    struct riscv64_sv_page_table *region_table = __va(phys_region_table);

    size_t virtual_index = sv_level_index_of_addr(level, vbase);
    for(size_t vi = virtual_index; vi < RISCV64_SV_ENTRIES_PER_LEVEL; vi++) {
        uint64_t *map_entry = &map_table->entries[vi];
        uint64_t *region_entry = &region_table->entries[vi - virtual_index];

        if(!(*region_entry & RISCV64_SV_VALID)) {
            // End of region
            break;
        }

        if(!(*map_entry & RISCV64_SV_VALID)) {
            // Something is wrong
            // (region was mapped incorrectly or this region is not mapped at all)
            return -EINVAL;
        }

        if(*map_entry == *region_entry) {
            // We can just zero the entry
            *map_entry = 0x0;
            continue;
        }
        else if(*map_entry & RISCV64_SV_VMEM_SHARED_MAP) {
            struct riscv64_sv_page_table __phys *phys_shared_table
                = sv_pointer_from_entry(*map_entry);
            struct riscv64_sv_page_table __phys *phys_region_subtable
                = sv_pointer_from_entry(*region_entry);
            res = sv_unmap_region_tables(
                    phys_shared_table,
                    phys_region_subtable,
                    level-1,
                    vbase + ((vi-virtual_index) * sv_level_page_size(level)),
                    map,
                    region);
            if(res) {
                return res;
            }
            int shared_table_empty = 1;
            struct riscv64_sv_page_table *shared_table = __va(phys_shared_table);
            for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL; i++) {
                if(shared_table->entries[i] & RISCV64_SV_VALID) {
                    shared_table_empty = 0;
                    break;
                }
            }
            if(shared_table_empty) {
                res = free_sv_page_tables(phys_shared_table, level-1);
                if(res) {
                    wprintk("Failed to free shared intermediate page table (Possibly Leaking Memory) (err=%s)\n",
                            errnostr(res));
                } else {
                    // Only clear the map entry if we freed the shared table
                    // (Hopefully won't leak memory if we fail to free)
                    *map_entry = 0x0;
                }
            }
        } else {
            // Either they should be exactly the same or it should be a shared table
            return -EINVAL;
        }
    }
    return 0;
}

int arch_vmem_map_map_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    int res;

    dprintk("arch_vmem_map_map_region(map=%p, ref=%p, vaddr=%p, size=%p)\n",
            map, ref,
            ref->virt_addr,
            ref->region->size);

    int level = map->arch_state.root_level;
    if(level < ref->region->arch_state.root_level) {
        eprintk("arch_vmem_map_map_region: invalid map->level < region->level (%d < %d)\n",
                (int)level, (int)ref->region->arch_state.root_level);
        return -EINVAL;
    }

    size_t region_root_page_size = sv_level_page_size(ref->region->arch_state.root_level);
    if((uintptr_t)ref->virt_addr % region_root_page_size) {
        return -EINVAL;
    }

    struct riscv64_sv_page_table __phys *phys_map_table = map->arch_state.root_table;
    while(level > ref->region->arch_state.root_level) {
        size_t index = sv_level_index_of_addr(level, ref->virt_addr);
        struct riscv64_sv_page_table *map_table = __va(phys_map_table);
        uint64_t *map_entry = &map_table->entries[index];

        if(RISCV64_SV_VALID & *map_entry) {
            phys_map_table = sv_pointer_from_entry(*map_entry);
        } else {
            // Allocate a shared empty table
            struct riscv64_sv_page_table __phys *shared_table;
            res = create_empty_sv_table(&shared_table);
            if(res) {
                return -ENOMEM;
            }

            res = create_sv_shared_table_entry(
                    map_entry,
                    level,
                    shared_table);
            if(res) {
                return res;
            }
            phys_map_table = shared_table;
        }

        level--;
    }

    res = sv_map_region_tables(
            phys_map_table,
            ref->region->arch_state.root_table,
            level,
            ref->virt_addr,
            map,
            ref->region);
    if(res) {
        return res;
    }

    return 0;
}
int arch_vmem_map_unmap_region(struct vmem_map *map, struct vmem_region_ref *ref)
{
    int res;

    DEBUG_ASSERT(ref->map == map);

    int level = map->arch_state.root_level;
    if(level < ref->region->arch_state.root_level) {
        eprintk("arch_vmem_map_unmap_region: invalid map->level < region->level (%d < %d)\n",
                (int)level, (int)ref->region->arch_state.root_level);
        return -EINVAL;
    }

    struct riscv64_sv_page_table __phys *phys_map_table = map->arch_state.root_table;
    while(level > ref->region->arch_state.root_level) {
        size_t index = sv_level_index_of_addr(level, ref->virt_addr);
        struct riscv64_sv_page_table *map_table = __va(phys_map_table);
        uint64_t *map_entry = &map_table->entries[index];

        if(RISCV64_SV_VALID & *map_entry) {
            DEBUG_ASSERT(*map_entry & RISCV64_SV_VMEM_SHARED_MAP);
            phys_map_table = sv_pointer_from_entry(*map_entry);
        } else {
            // We should be able to walk down to the region
            return -EINVAL;
        }

        level--;
    }

    res = sv_unmap_region_tables(
            phys_map_table,
            ref->region->arch_state.root_table,
            level,
            ref->virt_addr,
            map,
            ref->region);
    if(res) {
        return res;
    }

    return 0;
}

int arch_vmem_map_activate(struct vmem_map *map)
{
    uint64_t satp_value =
        riscv64_format_satp(map->arch_state.root_table, map->arch_state.root_level);

    write_csr(satp, satp_value);

    riscv64_flush_tlb();

    return 0;
}

static void
tlb_shootdown_xcall(void *_map) {

    // Disable IRQs to make absolutely sure we can't change the
    // value of cr3 by accident
    int irq_flags = disable_save_irqs();

    if(vmem_map_get_current() == _map) {
        riscv64_flush_tlb();
    }

    enable_restore_irqs(irq_flags);
}

int arch_vmem_map_flush(struct vmem_map *map)
{
    if(map->active_on <= 0) {
        return 0;
    }

    if((map->active_on == 1)
      && map == vmem_map_get_current()) {
        riscv64_flush_tlb();
        return 0;
    }

    int res = xcall_broadcast(tlb_shootdown_xcall, map);
    if(res) {
        return res;
    }

    return 0;
}

int arch_vmem_paged_region_map(
        struct vmem_region *region,
        size_t offset,
        void __phys * phys_addr,
        size_t size,
        unsigned long flags)
{
    int res;

    dprintk("arch_vmem_paged_region_map: region=%p, offset=%p, phys_addr=%p, size=%p\n",
            region,
            offset,
            phys_addr,
            size);

    size_t root_page_size = sv_level_page_size(region->arch_state.root_level);
    struct riscv64_sv_page_table __phys *phys_root = region->arch_state.root_table;
    struct riscv64_sv_page_table *root = __va(phys_root);

    if(size % RISCV64_SV_PAGE_SIZE_LEVEL_0) {
        return -EINVAL;
    }
    if((uintptr_t)phys_addr % RISCV64_SV_PAGE_SIZE_LEVEL_0) {
        return -EINVAL;
    }
    if((uintptr_t)offset % RISCV64_SV_PAGE_SIZE_LEVEL_0) {
        return -EINVAL;
    }

    while(size > 0) {
        int entry_level = 0;

        struct riscv64_sv_page_table __phys *cur_phys_table = phys_root;
        int cur_level = region->arch_state.root_level;
        size_t cur_offset = offset % sv_level_page_size(cur_level+1);

        dprintk("arch_vmem_paged_region_map(offset=0x%lx, phys_addr=%p, size=0x%lx)\n",
                offset,
                phys_addr,
                size);

        do {
            size_t cur_page_size = sv_level_page_size(cur_level);
            struct riscv64_sv_page_table *cur_table = __va(cur_phys_table);
            size_t cur_index = cur_offset / cur_page_size;
            if(cur_index > RISCV64_SV_ENTRIES_PER_LEVEL) {
                eprintk("arch_vmem_paged_region_map(offset=0x%lx) offset is too large for page table!\n",
                        offset);
                return -EINVAL;
            }
            uint64_t *cur_entry = &cur_table->entries[cur_index];
            if(*cur_entry & RISCV64_SV_VALID)
            {
                DEBUG_ASSERT(!RISCV64_SV_ENTRY_IS_LEAF(*cur_entry));
                DEBUG_ASSERT(!(*cur_entry & RISCV64_SV_VMEM_SHARED_MAP));

                cur_phys_table = sv_pointer_from_entry(*cur_entry);
            }
            else
            {
                struct riscv64_sv_page_table __phys *phys_subtable;

                res = create_empty_sv_table(&phys_subtable);
                if(res) {
                    return res;
                }

                res = create_sv_table_entry(
                        cur_entry,
                        cur_level,
                        phys_subtable);
                if(res) {
                    return res;
                }

                cur_offset = cur_offset % cur_page_size;
                cur_phys_table = phys_subtable;
            }
            cur_level--;

        } while(cur_level != entry_level);

        struct riscv64_sv_page_table *cur_table = __va(cur_phys_table);
        size_t cur_index = cur_offset / sv_level_page_size(cur_level);
        uint64_t *entry = &cur_table->entries[cur_index];

        res = create_sv_leaf_entry(
                entry,
                cur_level,
                phys_addr,
                flags);
        if(res) {
            return res;
        }

        dprintk("Created Leaf Entry 0x%lx at level=%d, offset=0x%lx, index=0x%lx, phys_addr=0x%lx\n",
                *entry,
                cur_level,
                offset,
                index,
                phys_addr);
        size_t page_size = sv_level_page_size(cur_level);
        offset += page_size;
        phys_addr += page_size;
        size -= page_size;
    }

    return 0;
}

int arch_vmem_paged_region_unmap(
        struct vmem_region *region,
        size_t offset,
        size_t size)
{
    int res;

    size_t root_page_size = sv_level_page_size(region->arch_state.root_level);
    struct riscv64_sv_page_table __phys *phys_root = region->arch_state.root_table;
    struct riscv64_sv_page_table *root = __va(phys_root);

    while(size > 0) {
        int entry_level = 0;

        struct riscv64_sv_page_table __phys *cur_phys_table = phys_root;
        int cur_level = region->arch_state.root_level;

        do {
            struct riscv64_sv_page_table *cur_table = __va(cur_phys_table);
            size_t cur_index = sv_level_index_of_addr(
                    cur_level,
                    (void*)offset);
            uint64_t *cur_entry = &cur_table->entries[cur_index];
            if(*cur_entry & RISCV64_SV_VALID)
            {
                DEBUG_ASSERT(!RISCV64_SV_ENTRY_IS_LEAF(*cur_entry));
                DEBUG_ASSERT(!(*cur_entry & RISCV64_SV_VMEM_SHARED_MAP));

                cur_phys_table = sv_pointer_from_entry(*cur_entry);
            }
            else
            {
                // We are unmapping, if it doesn't exist, then our job is already done
                break;
            }
            cur_level--;

        } while(cur_level != entry_level);

        struct riscv64_sv_page_table *cur_table = __va(cur_phys_table);
        size_t index = sv_level_index_of_addr(cur_level, (void*)offset);
        uint64_t *entry = &cur_table->entries[index];

        DEBUG_ASSERT(
                !(*entry & RISCV64_SV_VALID) ||
                RISCV64_SV_ENTRY_IS_LEAF(*entry));

        // Invalidate the mapping
        *entry = 0x0;

        size_t page_size = sv_level_page_size(cur_level);
        offset += page_size;
        size -= page_size;
    }

    return 0;
}

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map)
{
    riscv64_dump_page_table(
            printer,
            map->arch_state.root_table,
            0x0,
            map->arch_state.root_level);
}

static struct vmem_region *kernel_map_region = NULL;

static int
riscv64_map_identity_map_region(void)
{
    int res;

    size_t map_size = (arch_kernel_phys_size() + 0xFFF) & ~0xFFF;
    kernel_map_region = vmem_region_create_direct(
            arch_kernel_phys_start(),
            map_size,
            VMEM_REGION_EXEC|VMEM_REGION_WRITE|VMEM_REGION_READ);

    if(kernel_map_region == NULL) {
        eprintk("OOM Error when initializing default kernel vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(
            kernel_map_region,
            (void*)CONFIG_RISCV64_KERNEL_VIRTUAL_BASE);
    if(res) {
        eprintk("Failed to map kernel vmem_region into default vmem_map! (err=%s)\n", errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(vmem, riscv64_map_identity_map_region, "Creating Kernel Virtual Memory Region");

// Returns 0 if not-present 1 if present, -ERRNO on error
int
riscv64_vmem_map_page_is_present(
        struct vmem_map *map,
        void *vaddr)
{
    int res;
    int irq_flags = spin_lock_irq_save(&map->lock);

    int level = map->arch_state.root_level;
    struct riscv64_sv_page_table __phys *phys_table =
        map->arch_state.root_table;

    while(level >= 0) {
        size_t index = sv_level_index_of_addr(level, vaddr);
        struct riscv64_sv_page_table *table = __va(phys_table);
        uint64_t *entry = &table->entries[index];
        if(!(*entry & RISCV64_SV_VALID)) {
            // Not-present
            spin_unlock_irq_restore(&map->lock, irq_flags);
            return 0;
        }
        if(RISCV64_SV_ENTRY_IS_LEAF(*entry)) {
            // It is present
            spin_unlock_irq_restore(&map->lock, irq_flags);
            return 1;
        }

        if(level == 0) {
            // Invalid page table
            spin_unlock_irq_restore(&map->lock, irq_flags);
            return -EINVAL;
        }

        // It is a table, traverse
        phys_table = sv_pointer_from_entry(*entry);
        level--;
    }

    spin_unlock_irq_restore(&map->lock, irq_flags);
    return 0;
}


