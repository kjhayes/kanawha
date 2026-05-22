
#include <kanawha/paging/pagetable.h>
#include <kanawha/paging/paging.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>

static int
paging_alloc_raw_empty_table(
        const struct paging_mode *mode,
        void __phys **table_ptr,
        int table_level)
{
    int res;

    order_t table_order;
    table_order = paging_level_table_order(mode, table_level);

    res = page_alloc(table_order, table_ptr, 0);
    if(res)
    {
        return -ENOMEM;
    }
    memset((void *)__va(*table_ptr), 0, 1UL<<table_order);

    return 0;
}

static int
paging_free_raw_table(const struct paging_mode *mode, void __phys *table, int level)
{
    int res;

    void *table_entries = (void *)__va(table);
    size_t num_entries = paging_level_num_entries(mode, level);
    size_t entry_size = paging_level_entry_size(mode, level);

    for(size_t i = 0; i < num_entries; i++)
    {
        void *entry = table_entries + (i * entry_size);
        unsigned long entry_flags;
        res = paging_entry_get_flags(mode, level, entry, &entry_flags);
        if(res)
        {
            wprintk("free_page_tables: failed to get entry flags!\n");
            return res;
        }

        // Skip not-present entries
        if(!(entry_flags & PAGING_ENTRY_PRESENT))
        {
            continue;
        }

        // We don't need to do anything for leaf entries
        if(entry_flags & PAGING_ENTRY_IS_LEAF)
        {
            continue;
        }

        // Don't free mapped in entries
        if(entry_flags & PAGING_ENTRY_MAP)
        {
            continue;
        }

        // This must be a present table
        void __phys *subtable;
        res = paging_entry_read_addr(mode, level, entry, &subtable);
        if(res)
        {
            wprintk(
                "free_page_tables: failed to get entry subtable address!\n");
            return res;
        }

        res = paging_free_raw_table(mode, subtable, level - 1);
        if(res)
        {
            return res;
        }
    }

    order_t table_order = paging_level_table_order(mode, level);
    res = page_free(table_order, table);
    if(res)
    {
        return res;
    }

    return 0;
}

int
pagetable_init(
        struct pagetable *pt,
        int root_level,
        int max_leaf_level,
        int min_map_level,
        unsigned long flags)
{
    int res;

    pt->root_level = root_level;
    pt->max_leaf_level = max_leaf_level;
    pt->min_map_level = min_map_level;

    const struct paging_mode *mode = current_paging_mode();
    res = paging_alloc_raw_empty_table(mode, &pt->root_table, pt->root_level);
    if(res) {
        return res;
    }

    return 0;
}

int
pagetable_deinit(
        struct pagetable *pt)
{
    const struct paging_mode *mode;
    mode = current_paging_mode();
    paging_free_raw_table(mode, pt->root_table, pt->root_level);
    return 0;
}

int
pagetable_root_level(
        struct pagetable *pt)
{
    return pt->root_level;
}

void __phys *
pagetable_root(
        struct pagetable *pt)
{
    return pt->root_table;
}

order_t
pagetable_virt_order(
        struct pagetable *table)
{
    const struct paging_mode *mode = current_paging_mode();
    return paging_level_table_region_order(mode, table->root_level);
}

// Raw Page Table/Leaf Creation

static int
paging_create_pt_entry(const struct paging_mode *mode,
                     void *entry,
                     int level,
                     void __phys *phys,
                     unsigned long entry_flags)
{
    int res;

    res = paging_entry_clear(mode, level, entry);
    if(res)
    {
        return res;
    }

    res = paging_entry_write_addr(mode, level, entry, phys);
    if(res)
    {
        return res;
    }

    res = paging_entry_set_flags(mode, level, entry, entry_flags);
    if(res)
    {
        return res;
    }
 
    return 0;
}

static int
paging_create_permissive_pt_table_entry(const struct paging_mode *mode,
                                 void *entry,
                                 int pt_level,
                                 void __phys *next_table)
{
    int res;

    DEBUG_ASSERT(pt_level > 0);

    res = paging_entry_clear(mode, pt_level, entry);
    if(res)
    {
        return res;
    }

    res = paging_entry_write_addr(mode, pt_level, entry, next_table);
    if(res)
    {
        return res;
    }

    unsigned long to_set;
    to_set = PAGING_ENTRY_PRESENT |
             PAGING_ENTRY_READABLE |
             PAGING_ENTRY_WRITEABLE |
             PAGING_ENTRY_EXECUTABLE |
             PAGING_ENTRY_USER_ACCESS |
             PAGING_ENTRY_KERNEL_ACCESS;
    res = paging_entry_set_flags(
        mode,
        pt_level,
        entry,
        to_set);
    if(res)
    {
        return res;
    }

    return 0;
}

// Drill

static inline int
pagetable_drill_page(
        struct pagetable *pt,
        void *vaddr,
        void __phys *phys,
        int drill_level,
        unsigned long drilled_entry_flags)
{
    int res;

    dprintk("pagetable_drill: v=%p, p=%p, flags=(%s%s%s%s%s%s%s%s%s)\n",
            vaddr,
            phys,
            drilled_entry_flags & PAGING_ENTRY_PRESENT ? "[PRESENT]" : "",
            drilled_entry_flags & PAGING_ENTRY_MAP ? "[MAP]" : "",
            drilled_entry_flags & PAGING_ENTRY_IS_LEAF ? "[LEAF]" : "",
            drilled_entry_flags & PAGING_ENTRY_READABLE ? "[READ]" : "",
            drilled_entry_flags & PAGING_ENTRY_WRITEABLE ? "[WRITE]" : "",
            drilled_entry_flags & PAGING_ENTRY_EXECUTABLE ? "[EXEC]" : "",
            drilled_entry_flags & PAGING_ENTRY_USER_ACCESS ? "[USER]" : "",
            drilled_entry_flags & PAGING_ENTRY_KERNEL_ACCESS ? "[KERNEL]" : "",
            drilled_entry_flags & PAGING_ENTRY_CACHE_DISABLE ? "[NOCACHE]" : ""
            );

    const struct paging_mode *mode = current_paging_mode();

    int cur_table_level = pt->root_level;
    void __phys *cur_table = pt->root_table;

    while(cur_table_level != drill_level) {
        size_t vindex =
            paging_level_addr_table_index(
                mode,
                cur_table_level,
                vaddr);
        size_t entry_size =
            paging_level_entry_size(mode, cur_table_level);

        void *cur_table_virt = __va(cur_table);
        void *cur_entry = cur_table_virt + (vindex * entry_size);

        unsigned long entry_flags;
        res = paging_entry_get_flags(
                mode,
                cur_table_level,
                cur_entry,
                &entry_flags);
        if(res) {
            return res;
        }

        void __phys *next_table;
        if(entry_flags & PAGING_ENTRY_PRESENT) {
            if(entry_flags & PAGING_ENTRY_IS_LEAF) {
                return -EINVAL;
            }

            if(entry_flags & PAGING_ENTRY_MAP) {
                return -EINVAL;
            }

            res = paging_entry_read_addr(
                    mode,
                    cur_table_level,
                    cur_entry,
                    &next_table);
            if(res) {
                return res;
            }
        } else {
            // We need to allocate a new table
            res = paging_alloc_raw_empty_table(
                    mode,
                    &next_table,
                    cur_table_level-1);
            if(res) {
                return res;
            }
            // Create a table entry
            res = paging_create_permissive_pt_table_entry(
                    mode,
                    cur_entry,
                    cur_table_level,
                    next_table);
            if(res) {
                paging_free_raw_table(mode, next_table, cur_table_level-1);
                return res;
            }
        }

        cur_table = next_table;
        cur_table_level--;
    }

    // We should be at the right level
    void __phys *drill_table_phys = cur_table;
    int drill_table_level = cur_table_level;

    size_t drill_vindex =
        paging_level_addr_table_index(
            mode,
            drill_table_level,
            vaddr);
    size_t entry_size =
        paging_level_entry_size(mode, drill_table_level);

    void *drill_table_virt = __va(drill_table_phys);
    void *drill_entry = drill_table_virt + (drill_vindex * entry_size);

    do { // See what we are overwriting
        unsigned long overwritten_flags;
        res = paging_entry_get_flags(
                mode,
                drill_table_level,
                drill_entry,
                &overwritten_flags);
        if(res) {
            return res;
        }
        if(overwritten_flags & PAGING_ENTRY_MAP) {
            break;
        }
        if(!(overwritten_flags & PAGING_ENTRY_PRESENT)) {
            break;
        }
        if(overwritten_flags & PAGING_ENTRY_IS_LEAF) {
            break;
        }

        // This a present (non-mapped) table,
        // get it's physical address and free the tables

        void __phys *overwritten_phys;
        res = paging_entry_read_addr(
                mode,
                drill_table_level,
                drill_entry,
                &overwritten_phys);
        if(res) {
            return res;
        }

        res = paging_free_raw_table(
                mode,
                overwritten_phys,
                drill_table_level-1);
        if(res) {
            return res;
        }

    } while(0);

    res = paging_create_pt_entry(
            mode,
            drill_entry,
            drill_table_level,
            phys,
            drilled_entry_flags);
    if(res) {
        return res;
    }

    return 0;
}

int
pagetable_walk_drill_page(
        struct pagetable *pt,
        void *vaddr,
        int level,
        void __phys **phys_out,
        unsigned long *flags_out)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
   
    void __phys *cur_table = pagetable_root(pt);
    int cur_table_level = pagetable_root_level(pt);
    while(cur_table_level != level) {
        size_t vindex =
            paging_level_addr_table_index(
                mode,
                cur_table_level,
                vaddr);
        size_t entry_size =
            paging_level_entry_size(mode, cur_table_level);

        void *cur_table_virt = __va(cur_table);
        void *cur_entry = cur_table_virt + (vindex * entry_size);

        unsigned long entry_flags;
        res = paging_entry_get_flags(
                mode,
                cur_table_level,
                cur_entry,
                &entry_flags);
        if(res) {
            return res;
        }

        void __phys *next_table;
        if(entry_flags & PAGING_ENTRY_PRESENT) {
            if(entry_flags & PAGING_ENTRY_IS_LEAF) {
                return -EINVAL;
            }

            if(entry_flags & PAGING_ENTRY_MAP) {
                return -EINVAL;
            }

            res = paging_entry_read_addr(
                    mode,
                    cur_table_level,
                    cur_entry,
                    &next_table);
            if(res) {
                return res;
            }
        } else {
            // We need to allocate a new table
            res = paging_alloc_raw_empty_table(
                    mode,
                    &next_table,
                    cur_table_level-1);
            if(res) {
                return res;
            }
            // Create a table entry
            res = paging_create_permissive_pt_table_entry(
                    mode,
                    cur_entry,
                    cur_table_level,
                    next_table);
            if(res) {
                paging_free_raw_table(mode, next_table, cur_table_level-1);
                return res;
            }
        }

        cur_table = next_table;
        cur_table_level--;
    }

    size_t vindex =
        paging_level_addr_table_index(
            mode,
            cur_table_level,
            vaddr);
    size_t entry_size =
        paging_level_entry_size(mode, cur_table_level);

    void *table_virt = __va(cur_table);
    void *entry = table_virt + (vindex * entry_size);

    void __phys *phys;
    res = paging_entry_read_addr(
            mode,
            cur_table_level,
            entry,
            &phys);
    if(res) {
        return res;
    }
    unsigned long entry_flags;
    res = paging_entry_get_flags(
            mode,
            cur_table_level,
            entry,
            &entry_flags);
    if(res) {
        return res;
    }

    if(entry_flags & PAGING_ENTRY_PRESENT) {
        *phys_out = phys;
        *flags_out = entry_flags;
        return 0;
    }

    if(cur_table_level > 0) {
        // Drill a table below us
        res = paging_alloc_raw_empty_table(
                mode,
                &phys,
                cur_table_level-1);
        if(res) {
            return res;
        }
        // Create a table entry
        res = paging_create_permissive_pt_table_entry(
                mode,
                entry,
                cur_table_level,
                phys);
        if(res) {
            paging_free_raw_table(mode, phys, cur_table_level-1);
            return res;
        }

        res = paging_entry_get_flags(
                mode,
                cur_table_level,
                entry,
                &entry_flags);
        if(res) {
            return res;
        }

        *phys_out = phys;
        *flags_out = entry_flags;
        return 0;
    }

    *phys_out = NULL;
    *flags_out = 0;
    return 0;
}

static int
pagetable_drill_direct(
        struct pagetable *pt,
        void *vaddr,
        void __phys *phys,
        size_t size,
        unsigned long entry_flags)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    order_t min_page_order = paging_level_entry_region_order(mode, 0);

    if(ptr_orderof(vaddr) < min_page_order) {
        return -EINVAL;
    }
    if(ptr_orderof(phys) < min_page_order) {
        return -EINVAL;
    }
    if(ptr_orderof(size) < min_page_order) {
        return -EINVAL;
    }
    // The requested mapping is aligned to the minimum
    // page size virtually/physically and is a multiple
    // of the minimum page size.
    
    void *viter = vaddr;
    void __phys *piter = phys;
    size_t remaining = size;
    while(remaining) {
        order_t page_order;
        int drill_level;
        for(drill_level = pt->max_leaf_level; drill_level > 0; drill_level--)
        {
            page_order = paging_level_entry_region_order(mode, drill_level);
            if(ptr_orderof(viter) < page_order) {
                continue;
            }
            if(ptr_orderof(piter) < page_order) {
                continue;
            }
            if(ptr_orderof(remaining) < page_order) {
                continue;
            }
            break;
        }
        if(drill_level == 0) {
            page_order = min_page_order;
        }

        size_t page_size = 1UL<<page_order;

        DEBUG_ASSERT_MSG(
                page_size <= remaining,
                "page_size=0x%lx, remaining=0x%lx",
                (ul_t)page_size,
                (ul_t)remaining);

        res = pagetable_drill_page(
                pt,
                viter,
                piter,
                drill_level,
                entry_flags);
        if(res) {
            return res;
        }

        viter += page_size;
        piter += page_size;
        remaining -= page_size;
    }

    return 0;
}

int
pagetable_drill(
        struct pagetable *pt,
        void *vaddr,
        void __phys *phys,
        size_t size,
        unsigned long entry_flags)
{
    return pagetable_drill_direct(
            pt,
            vaddr,
            phys,
            size,
            entry_flags | PAGING_ENTRY_IS_LEAF | PAGING_ENTRY_PRESENT);
}

int
pagetable_undrill(
        struct pagetable *pt,
        void *vaddr,
        size_t size)
{
    return pagetable_drill_direct(
            pt,
            vaddr,
            (void __phys *)0,
            size,
            PAGING_ENTRY_IS_LEAF);
}

// Map
int
pagetable_map(
        struct pagetable *parent,
        struct pagetable *child,
        void *vaddr,
        size_t size)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    order_t min_page_order = paging_level_entry_region_order(mode, child->min_map_level);

    if(ptr_orderof(vaddr) < min_page_order) {
        return -EINVAL;
    }
    if(ptr_orderof(size) < min_page_order) {
        return -EINVAL;
    }

    // minimum of two maximums
    void *viter = vaddr;
    void *child_viter = NULL;
    size_t remaining = size;
    while(remaining) {
        order_t page_order;
        int drill_level;
        for(drill_level = parent->max_leaf_level; drill_level >= child->min_map_level; drill_level--)
        {
            page_order = paging_level_entry_region_order(mode, drill_level);
            if(ptr_orderof(viter) < page_order) {
                continue;
            }
            if(ptr_orderof(remaining) < page_order) {
                continue;
            }
            break;
        }
        DEBUG_ASSERT(drill_level >= 0);

        size_t page_size = 1UL<<page_order;

        DEBUG_ASSERT(remaining >= page_size);

        void __phys *phys;
        unsigned long entry_flags;
        res = pagetable_walk_drill_page(
                child,
                child_viter,
                drill_level,
                &phys,
                &entry_flags);
        if(res) {
            return res;
        }

        res = pagetable_drill_page(
                parent,
                viter,
                phys,
                drill_level,
                entry_flags | PAGING_ENTRY_MAP);
        if(res) {
            return res;
        }

        viter += page_size;
        child_viter += page_size;
        remaining -= page_size;
    }

    return 0;
}

int
pagetable_unmap(
        struct pagetable *pt,
        void *vaddr,
        size_t size)
{
    int res;

    const struct paging_mode *mode = current_paging_mode();
    order_t min_page_order = paging_level_entry_region_order(mode, 0);

    if(ptr_orderof(vaddr) < min_page_order) {
        return -EINVAL;
    }
    if(ptr_orderof(size) < min_page_order) {
        return -EINVAL;
    }

    int root_level = pagetable_root_level(pt);
    void __phys *root_table = pagetable_root(pt);

    void *viter = vaddr;
    size_t remaining = size;
    while(remaining) {
        int cur_table_level = root_level;
        void __phys *cur_table = root_table;

        int level_unmapped = -1;
        while(cur_table_level >= 0) {
            size_t vindex = paging_level_addr_table_index(
                    mode,
                    cur_table_level,
                    viter);
            size_t entry_size = paging_level_entry_size(mode, cur_table_level);
            void *table_virt = __va(cur_table);
            void *entry = table_virt + (entry_size * vindex);

            unsigned long entry_flags;
            res = paging_entry_get_flags(
                    mode,
                    cur_table_level,
                    entry,
                    &entry_flags);
            if(res) {
                return res;
            }

            if(entry_flags & PAGING_ENTRY_PRESENT) {
                if(entry_flags & PAGING_ENTRY_MAP) {
                    // Unmap regardless of whether it is a leaf or a table
                    res = paging_entry_clear(mode, cur_table_level, entry);
                    if(res) {
                        return res;
                    }
                    level_unmapped = cur_table_level;
                    break;
                }
                if(entry_flags & PAGING_ENTRY_IS_LEAF) {
                    // It's a direct leaf?
                    panic("Unexpected non-PAGING_ENTRY_MAP leaf during pagetable_unmap!\n");

                    // level_unmapped = cur_table_level;
                    break;
                } else {
                    // It's a (non-PAGING_ENTRY_MAP) table, descend
                    void __phys *next_table;
                    res = paging_entry_read_addr(
                            mode,
                            cur_table_level,
                            entry,
                            &next_table);
                    if(res) {
                        return res;
                    }
                    cur_table = next_table;
                    cur_table_level--;
                    continue;
                }
            } else {
                level_unmapped = cur_table_level;
                break;
            }
        }

        if(level_unmapped < 0) {
            return -EINVAL;
        }

        order_t page_order = paging_level_entry_region_order(mode, level_unmapped);
        viter += (1UL<<page_order);
        remaining -= (1UL<<page_order);

        DEBUG_ASSERT(ptr_orderof(viter) >= min_page_order);
        DEBUG_ASSERT(ptr_orderof(remaining) >= min_page_order);
    }

    return 0;
}

int
pagetable_walk_leaf(
        struct pagetable *pt,
        void *vaddr,
        void __phys **page_out,
        order_t *page_order_out,
        unsigned long *entry_flags_out)
{
    int res;
    const struct paging_mode *mode = current_paging_mode();

    void __phys *cur_table = pagetable_root(pt);
    int cur_table_level = pagetable_root_level(pt);
    while(cur_table_level >= 0) {
        size_t vindex =
            paging_level_addr_table_index(
                mode,
                cur_table_level,
                vaddr);
        size_t entry_size =
            paging_level_entry_size(mode, cur_table_level);

        void *cur_table_virt = __va(cur_table);
        void *cur_entry = cur_table_virt + (vindex * entry_size);

        unsigned long entry_flags;
        res = paging_entry_get_flags(
                mode,
                cur_table_level,
                cur_entry,
                &entry_flags);
        if(res) {
            return res;
        }

        void __phys *entry_phys;
        res = paging_entry_read_addr(
                mode,
                cur_table_level,
                cur_entry,
                &entry_phys);
        if(res) {
            return res;
        }

        if(entry_flags & PAGING_ENTRY_IS_LEAF) {
            *page_out = entry_phys;
            *page_order_out = paging_level_entry_region_order(mode, cur_table_level);
            *entry_flags_out = entry_flags;
            return 0;
        }

        if(entry_flags & PAGING_ENTRY_PRESENT) {
            // Descend a Level
            cur_table = entry_phys;
            cur_table_level--;
            continue;

        }
        return -ENXIO;
    }
    return -ENXIO;
}

static int
pagetable_dump_subtable(
        printk_f *printer,
        const struct paging_mode *mode,
        void __phys *table_phys_addr,
        int level,
        void *virt_base,
        int is_root)
{
    int res = 0;

    int num_levels = paging_mode_num_levels(mode);

    if(level >= num_levels || level < 0)
    {
        (*printer)("dump_page_table somehow reached invalid table level (%d)\n",
                   level);
        return -EINVAL;
    }

    int num_tabs = num_levels - level;
#define PUT_TABS()                                                             \
    for(int __tab = 0; __tab < num_tabs; __tab++)                              \
    {                                                                          \
        (*printer)("  ");                                                      \
    }

    size_t entry_region_size = paging_level_entry_region_size(mode, level);
    size_t num_entries = paging_level_num_entries(mode, level);

    void *table = (void *)__va(table_phys_addr);

    int leaf_pending = 0;

    void __phys *pending_next_paddr = 0;
    void __phys *pending_paddr = 0;
    void *pending_vaddr = 0;
    size_t pending_size = 0;
    int pending_index = 0;
    int pending_final_index = 0;
    uint64_t pending_flags = 0;

#define DUMP_PENDING_LEAF()                                                    \
    do                                                                         \
    {                                                                          \
        PUT_TABS();                                                            \
        (*printer)("[level(%d)", level);                                       \
        if(pending_index == pending_final_index)                               \
        {                                                                      \
            (*printer)(" index(%d)", pending_index);                           \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            (*printer)(" indices(%d to %d)",                                   \
                       pending_index,                                          \
                       pending_final_index);                                   \
        }                                                                      \
        (*printer)("] ");                                                      \
        (*printer)("%p -> %p [size=0x%llx]",                                   \
                   pending_vaddr,                                              \
                   pending_paddr,                                              \
                   (ull_t)pending_size);                                       \
        (*printer)("%s%s%s%s%s%s%s", \
                pending_flags & PAGING_ENTRY_PRESENT ? "[PRESENT]" : "", \
                pending_flags & PAGING_ENTRY_READABLE ? "[READ]" : "", \
                pending_flags & PAGING_ENTRY_WRITEABLE ? "[WRITE]" : "", \
                pending_flags & PAGING_ENTRY_EXECUTABLE ? "[EXEC]" : "", \
                pending_flags & PAGING_ENTRY_USER_ACCESS ? "[USER]" : "", \
                pending_flags & PAGING_ENTRY_KERNEL_ACCESS ? "[KERNEL]" : "", \
                "");\
        (*printer)("\n"); \
    } while(0)

    size_t entry_size = paging_level_entry_size(mode, level);

    for(size_t entry_index = 0; entry_index < num_entries; entry_index++)
    {
        if(is_root && (entry_index == (num_entries / 2)))
        {
            virt_base = (void *)((uint64_t)virt_base);
            if(leaf_pending)
            {
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            }
        }

        void *entry = table + (entry_index * entry_size);

        void __phys *addr;
        res = paging_entry_read_addr(mode, level, entry, &addr);
        DEBUG_ASSERT(res == 0);

        unsigned long flags;
        res = paging_entry_get_flags(mode, level, entry, &flags);
        DEBUG_ASSERT(res == 0);

        if(!(flags & PAGING_ENTRY_PRESENT))
        {
            // Not Present, continue.
            virt_base += entry_region_size;
            continue;
        }

        int is_leaf = flags & PAGING_ENTRY_IS_LEAF;
        DEBUG_ASSERT(is_leaf || (!(flags & PAGING_ENTRY_IS_LEAF)));

        if(leaf_pending)
        {
            if(!is_leaf)
            {
                // Dump the pending leaf because we are going down
                // a level
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            }
            else if((flags != pending_flags) || (addr != pending_next_paddr))
            {
                // Dump the pending leaf because some flag or
                // address changed
                dprintk("dumping because changed status (expected paddr=%p, got %p) (expected flags=0x%lx, got 0x%lx)\n",
                        pending_next_paddr,
                        addr,
                        pending_flags,
                        flags);
                DUMP_PENDING_LEAF();
                leaf_pending = 1;
                pending_index = entry_index;
                pending_final_index = entry_index;
                pending_paddr = addr;
                pending_next_paddr = addr + entry_region_size;
                pending_vaddr = virt_base;
                pending_size = entry_region_size;
                pending_flags = flags;
            }
            else
            {
                // Don't dump the leaf, just extend it
                leaf_pending = 1;
                pending_size += entry_region_size;
                pending_next_paddr += entry_region_size;
                pending_final_index = entry_index;
            }
        }
        else
        {
            if(is_leaf)
            {
                leaf_pending = 1;
                pending_index = entry_index;
                pending_final_index = entry_index;
                pending_paddr = addr;
                pending_next_paddr = addr + entry_region_size;
                pending_vaddr = virt_base;
                pending_size = entry_region_size;
                pending_flags = flags;
            }
        }

        if(!is_leaf)
        {
            PUT_TABS();
            (*printer)("[level(%d) index(%d) virt(%p-%p)] ",
                    level,
                    entry_index,
                    virt_base,
                    virt_base + entry_region_size);
            uint64_t shared_mask;
            (*printer)("Table %s (%p)\n",
                       flags & PAGING_ENTRY_MAP ? "[MAP]" : "",
                       addr);
            res = pagetable_dump_subtable(printer, mode, addr, level - 1, virt_base, 0);
            if(res)
            {
                return res;
            }
        }

        virt_base += entry_region_size;
    }

    if(leaf_pending)
    {
        leaf_pending = 0;
        DUMP_PENDING_LEAF();
    }

#undef PUT_TABS
#undef DUMP_PENDING_LEAF

    return res;
}

int
pagetable_dump(
        printk_f *printer,
        struct pagetable *pt)
{
    return pagetable_dump_subtable(
            printer,
            current_paging_mode(),
            pagetable_root(pt),
            pagetable_root_level(pt),
            (void*)0x0,
            1);
}

