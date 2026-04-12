
#include <kanawha/paging/paging.h>
#include <kanawha/assert.h>
#include <kanawha/excp.h>
#include <kanawha/init.h>
#include <kanawha/irq_domain.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/xcall.h>

#define PAGING_PT_ENTRY_BUFLEN (8)

static inline struct vmem_map_paging_state *
vmem_map_get_paging_state(
        struct vmem_map *map)
{
    return arch_get_vmem_map_paging_state(map);
}
static inline struct vmem_region_paging_state *
vmem_region_get_paging_state(
        struct vmem_region *region)
{
    return arch_get_vmem_region_paging_state(region);
}

static int
create_pt_leaf_entry(
        const struct paging_mode *mode,
        void *entry,
        int pt_level,
        void __phys *base,
        unsigned long flags)
{
    int res;

    res = paging_entry_clear(
            mode,
            pt_level,
            entry);
    if(res) {
        return res;
    }

    res = paging_entry_write_addr(
            mode,
            pt_level,
            entry,
            base);
    if(res) {
        return res;
    }

    unsigned long paging_flags = 0;
    paging_flags |= PAGING_ENTRY_PRESENT;
    paging_flags |= PAGING_ENTRY_IS_LEAF;
    paging_flags |= PAGING_ENTRY_KERNEL_ACCESS;
    if(flags & VMEM_REGION_READ) {
        paging_flags |= PAGING_ENTRY_READABLE;
    }
    if(flags & VMEM_REGION_WRITE) {
        paging_flags |= PAGING_ENTRY_WRITEABLE;
    }
    if(flags & VMEM_REGION_EXEC) {
        paging_flags |= PAGING_ENTRY_EXECUTABLE;
    }
    if(flags & VMEM_REGION_USER) {
        paging_flags |= PAGING_ENTRY_USER_ACCESS;
    }
    if(flags & VMEM_REGION_NOCACHE) {
        paging_flags |= PAGING_ENTRY_CACHE_DISABLE;
    }

    res = paging_entry_set_flags(
            mode,
            pt_level,
            entry,
            paging_flags);
    if(res) {
        return res;
    }

    return 0;
}

static int
create_permissive_pt_table_entry(
        const struct paging_mode *mode,
        void *entry,
        int pt_level,
        void __phys *next_table)
{
    int res;

    DEBUG_ASSERT(ptr_orderof(next_table) >= 12);

    res = paging_entry_clear(
            mode,
            pt_level,
            entry);
    if(res) {
        return res;
    }

    res = paging_entry_write_addr(
            mode,
            pt_level,
            entry,
            next_table);
    if(res) {
        return res;
    }

    res = paging_entry_set_flags(
            mode,
            pt_level,
            entry,
             PAGING_ENTRY_PRESENT
            |PAGING_ENTRY_IS_TABLE
            |PAGING_ENTRY_READABLE
            |PAGING_ENTRY_WRITEABLE
            |PAGING_ENTRY_EXECUTABLE
            |PAGING_ENTRY_USER_ACCESS
            |PAGING_ENTRY_KERNEL_ACCESS
            );
    if(res) {
        return res;
    }

    return 0;
}

static int
create_shared_pt_table_entry(
        const struct paging_mode *mode,
        void *entry,
        int pt_level,
        void __phys *next_table)
{
    int res;

    res = create_permissive_pt_table_entry(
            mode,
            entry,
            pt_level,
            next_table);
    if(res)
    {
        return res;
    }

    res = paging_entry_set_flags(
            mode,
            pt_level,
            entry,
            PAGING_ENTRY_SHARED);
    if(res) {
        return res;
    }

    return 0;
}

static int
create_pt_table_entry(
        const struct paging_mode *mode,
        void *entry,
        int pt_level,
        void __phys *next_table,
        unsigned long flags)
{
    int res;

    res = paging_entry_clear(
            mode,
            pt_level,
            entry);
    if(res) {
        return res;
    }

    res = paging_entry_write_addr(
            mode,
            pt_level,
            entry,
            next_table);
    if(res) {
        return res;
    }

    unsigned long paging_flags = 0;
    paging_flags |= PAGING_ENTRY_PRESENT;
    paging_flags |= PAGING_ENTRY_IS_TABLE;
    paging_flags |= PAGING_ENTRY_KERNEL_ACCESS;
    if(flags & VMEM_REGION_READ) {
        paging_flags |= PAGING_ENTRY_READABLE;
    }
    if(flags & VMEM_REGION_WRITE) {
        paging_flags |= PAGING_ENTRY_WRITEABLE;
    }
    if(flags & VMEM_REGION_EXEC) {
        paging_flags |= PAGING_ENTRY_EXECUTABLE;
    }
    if(flags & VMEM_REGION_USER) {
        paging_flags |= PAGING_ENTRY_USER_ACCESS;
    }

    res = paging_entry_set_flags(
            mode,
            pt_level,
            entry,
            paging_flags);
    if(res) {
        return res;
    }

    return 0;
}

static int
create_empty_pt_table(
        const struct paging_mode *mode,
        void __phys **table_ptr,
        int table_level)
{
    int res;

    size_t table_size;
    table_size = paging_level_table_size(mode, table_level);

    res = page_alloc(ptr_orderof(table_size), table_ptr, 0);
    if(res)
    {
        return -ENOMEM;
    }
    memset((void *)__va(*table_ptr), 0, table_size);

    return 0;
}

static int
create_paged_pt_table(
        const struct paging_mode *mode,
        void __phys **table_ptr,
        int table_level,
        size_t size)
{
    int res;

    size_t entry_region_size;
    size_t entry_size;

    entry_region_size = paging_level_entry_region_size(mode, table_level);
    entry_size = paging_level_entry_size(mode, table_level);

    // If we fail later we don't actually free this (TODO)
    res = create_empty_pt_table(mode, table_ptr, table_level);
    if(res)
    {
        return res;
    }

    // Map in the region as if we started at the virtual base of this table
    size_t num_whole_entries = size / entry_region_size;
    DEBUG_ASSERT(num_whole_entries <= paging_level_num_entries(mode, table_level));

    for(size_t i = 0; i < num_whole_entries; i++)
    {
        // Map the middle entries
        void __phys *subtable;
        res = create_empty_pt_table(
                mode,
                &subtable,
                table_level - 1);
        if(res)
        {
            return res;
        }
        res =
            create_permissive_pt_table_entry(
                    mode,
                    ((void*)__va(*table_ptr)) + (i * entry_size),
                    table_level,
                    subtable);
        if(res)
        {
            return res;
        }
    }

    size_t final_entry_size = size - (num_whole_entries * entry_region_size);
    if(final_entry_size > 0)
    {
        void __phys *subtable;
        res =
            create_paged_pt_table(
                    mode,
                    &subtable,
                    table_level - 1,
                    final_entry_size);
        if(res)
        {
            return res;
        }
        res = create_permissive_pt_table_entry(
                mode,
                ((void *)__va(*table_ptr)) + (num_whole_entries * entry_size),
                table_level,
                subtable);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
create_direct_pt_table(const struct paging_mode *mode,
                       void __phys **table_ptr,
                       int table_level,
                       void __phys *base,
                       size_t size,
                       unsigned long flags)
{
    int res;

    size_t entry_region_size;
    size_t entry_size;
    int entry_can_be_leaf;

    entry_region_size = paging_level_entry_region_size(mode, table_level);
    entry_size = paging_level_entry_size(mode, table_level);
    entry_can_be_leaf = paging_level_can_be_leaf(mode, table_level);

    // If we fail later we don't actually free this (TODO)
    res = create_empty_pt_table(mode, table_ptr, table_level);
    if(res)
    {
        return res;
    }

    // Map in the region as if we started at the virtual base of this table
    size_t num_whole_entries = size / entry_region_size;
    DEBUG_ASSERT(num_whole_entries <= paging_level_num_entries(mode, table_level));

    for(size_t i = 0; i < num_whole_entries; i++)
    {
        // Map the middle entries
        if(entry_can_be_leaf)
        {
            res = create_pt_leaf_entry(
                    mode,
                    ((void*)__va(*table_ptr)) + (i * entry_size),
                    table_level,
                    base + (entry_region_size * i),
                    flags);
            if(res)
            {
                return res;
            }
        }
        else
        {
            void __phys *subtable;
            res = create_direct_pt_table(
                    mode,
                    &subtable,
                    table_level - 1,
                    base + (entry_region_size * i),
                    entry_region_size,
                    flags);
            if(res)
            {
                return res;
            }
            res = create_pt_table_entry(
                    mode,
                    ((void*)__va(*table_ptr)) + (i * entry_size),
                    table_level,
                    subtable,
                    flags);
            if(res)
            {
                return res;
            }
        }
    }

    size_t final_entry_size = size - (num_whole_entries * entry_region_size);

    if(final_entry_size > 0)
    {
        // We need to map the first entry as a table
        void __phys *subtable;
        res = create_direct_pt_table(
            mode,
            &subtable,
            table_level - 1,
            base + (num_whole_entries * entry_region_size),
            final_entry_size,
            flags);
        if(res)
        {
            return res;
        }
        res = create_pt_table_entry(
                mode,
                ((void*)__va(*table_ptr)) + (num_whole_entries * entry_size),
                table_level,
                subtable,
                flags);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
arch_vmem_region_init_direct(struct vmem_region *region)
{
    int res;

    const struct paging_mode *mode = arch_paging_mode();

    order_t min_page_order = paging_level_entry_region_order(mode, 0);
    size_t min_page_size = 1ULL<<min_page_order;

    if((uintptr_t)region->direct.phys_base % min_page_size != 0)
    {
        eprintk("Tried to initialize direct region with physical base "
                "unaligned from smallest page size!\n"
                "    region_base=%p, min_page_size=%p\n",
                region->direct.phys_base,
                (uintptr_t)min_page_size);
        return -EINVAL;
    }
    if(region->size % min_page_size != 0)
    {
        eprintk("Tried to initialize direct region with size that isn't a "
                "multiple of the smallest page size!\n",
                "    region_size=%p, min_page_size=%p\n",
                region->size,
                (uintptr_t)min_page_size);
        return -EINVAL;
    }

    uintptr_t base = (uintptr_t)region->direct.phys_base;
    uintptr_t end = (uintptr_t)(base + (region->size - 1));

    struct vmem_region_paging_state *pt_state =
        vmem_region_get_paging_state(region);

    pt_state->pt_level = -1;
    size_t pt_level_region_size = -1;
    int can_be_leaf = 0;

    int num_levels = paging_mode_num_levels(mode);

    for(int level = 0; level < num_levels-1; level++) {
        size_t table_region_size = paging_level_table_region_size(mode, level+1);
        if((region->size <= table_region_size) &&
           (base / table_region_size == end / table_region_size))
        {
            pt_state->pt_level = level+1;
            pt_level_region_size = table_region_size;
            can_be_leaf = paging_level_can_be_leaf(mode, level);
        }
    }

    if(pt_state->pt_level < 0)
    {
        eprintk("Could not find a page table level which would work for "
                "vmem_region [%p - %p)!\n",
                (uintptr_t)region->direct.phys_base,
                (uintptr_t)(region->direct.phys_base + region->size));
        return -EINVAL;
    }

    size_t entry_size = paging_level_entry_size(mode, pt_state->pt_level);
    DEBUG_ASSERT(entry_size <= PAGING_PT_ENTRY_BUFLEN);

    if(can_be_leaf && region->size == pt_level_region_size)
    {
        pt_state->entry_only = 1;
        res = create_pt_leaf_entry(
                mode,
                &pt_state->pt_entry_buffer,
                pt_state->pt_level,
                region->direct.phys_base,
                region->direct.flags);
        if(res)
        {
            return res;
        }
    }
    else
    {
        pt_state->entry_only = 0;
        res = create_direct_pt_table(
                mode,
                &pt_state->pt_table,
                pt_state->pt_level,
                region->direct.phys_base,
                region->size,
                region->direct.flags);
        if(res)
        {
            return res;
        }
        res = create_pt_table_entry(
                mode,
                &pt_state->pt_entry_buffer,
                pt_state->pt_level + 1,
                pt_state->pt_table,
                region->direct.flags);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
arch_vmem_region_init_paged(struct vmem_region *region)
{
    int res;

    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    int num_levels = paging_mode_num_levels(mode);
    if(num_levels <= 1) {
        return -EINVAL;
    }

    size_t min_table_size = paging_level_table_region_size(mode, 0);

    if(region->size % min_table_size != 0)
    {
        eprintk("Tried to initialize paged region with size that isn't a "
                "multiple of the smallest page table size!\n"
                "    region_size=%p, min_table_size=%p\n",
                region->size,
                (uintptr_t)min_table_size);
        return -EINVAL;
    }

    uintptr_t base = 0;
    uintptr_t end = (region->size - 1);

    struct vmem_region_paging_state *pt_state =
        vmem_region_get_paging_state(region);

    pt_state->pt_level = -1;

    for(int level = 1; level < num_levels; level++) {
        size_t table_region_size = paging_level_table_region_size(mode, level);
        if((region->size < table_region_size) &&
           ((base / table_region_size) == (end / table_region_size)))
        {
            pt_state->pt_level = level;
            break;
        }
    }

    pt_state->paged_max_entry_level = 1;

    if(pt_state->pt_level < 0)
    {
        eprintk("Could not find a page table level which would work for paged "
                "vmem_region [%p - %p)!\n",
                (uintptr_t)0,
                (uintptr_t)region->size);
        return -EINVAL;
    }

    pt_state->entry_only = 0;
    res = create_paged_pt_table(
            mode,
            &pt_state->pt_table,
            pt_state->pt_level,
            region->size);
    if(res)
    {
        return res;
    }
    DEBUG_ASSERT(PAGING_PT_ENTRY_BUFLEN
                 >= paging_level_entry_size(mode, pt_state->pt_level+1));
    res = create_permissive_pt_table_entry(
            mode,
            &pt_state->pt_entry_buffer,
            pt_state->pt_level + 1,
            pt_state->pt_table);
    if(res)
    {
        return res;
    }

    return 0;
}

int
arch_vmem_region_init(struct vmem_region *region)
{
    switch(region->type)
    {
    case VMEM_REGION_TYPE_DIRECT:
        return arch_vmem_region_init_direct(region);
    case VMEM_REGION_TYPE_PAGED:
        return arch_vmem_region_init_paged(region);
    default:
        return -EINVAL;
    }
}

order_t
arch_vmem_region_alignment(struct vmem_region *region)
{
    order_t order;
    const struct paging_mode *mode = arch_paging_mode();
    if(region->type == VMEM_REGION_TYPE_DIRECT) {
        order = paging_level_entry_region_order(mode, 0);
    } else {
        order = paging_level_entry_region_order(mode, 1);
    }
    return order;
}

static int
map_region_tables(const struct paging_mode *mode,
                  void __phys *map_table,
                  void __phys *region_table,
                  int table_level,
                  void *vbase,
                  struct vmem_map *map,
                  struct vmem_region *region)
{
    int res;

    int num_levels = paging_mode_num_levels(mode);

    size_t level_below_size;
    size_t entry_size;
    size_t entry_region_size;
    size_t num_possible_entries;
    size_t vindex;

    entry_size = paging_level_entry_size(mode, table_level);
    entry_region_size = paging_level_entry_region_size(mode, table_level);
    num_possible_entries = paging_level_num_entries(mode, table_level);
    vindex = paging_level_addr_table_index(mode, table_level, vbase);

    if(table_level > 1)
    {
        level_below_size = paging_level_table_size(mode, table_level - 1);
    }
    else
    {
        level_below_size = 0;
    }

    DEBUG_ASSERT(table_level < num_levels);

    for(size_t vi = vindex; vi < num_possible_entries; vi++)
    {
        void *map_entry;
        void *region_entry;

        map_entry = ((void*)__va(map_table)) + (vi * entry_size);
        region_entry = ((void*)__va(region_table)) + ((vi - vindex) * entry_size);

        unsigned long map_entry_flags;
        paging_entry_get_flags(
                mode,
                table_level,
                map_entry,
                &map_entry_flags);

        unsigned long region_entry_flags;
        paging_entry_get_flags(
                mode,
                table_level,
                region_entry,
                &region_entry_flags);

        if(!(region_entry_flags & PAGING_ENTRY_PRESENT))
        {
            // Region isn't present, so this is the end of the region
            break;
        }

        if(!(map_entry_flags & PAGING_ENTRY_PRESENT))
        {
            // Map isn't present, we can map in the region table
            // directly
            dprintk("map_table %p level %lld, entry %lld is not present, "
                    "overriding\n",
                    map_table,
                    table_level,
                    vi);
            memcpy(map_entry, region_entry, entry_size);
            continue;
        }

        int map_is_leaf = map_entry_flags & PAGING_ENTRY_IS_LEAF;
        int region_is_leaf = region_entry_flags & PAGING_ENTRY_IS_LEAF;

        DEBUG_ASSERT(region->type != VMEM_REGION_TYPE_PAGED || !region_is_leaf);

        if(map_is_leaf || region_is_leaf)
        {
            // OVERLAP!!!
            // We should've caught that already???
            panic("Unexpected vmem region overlap in map_region_tables! "
                  "(vaddr=%p, table_level=%d)\n",
                  vbase + (entry_region_size * (vi - vindex)),
                  table_level);
            return -EINVAL;
        }

        void __phys *region_next_addr;
        paging_entry_read_addr(
                mode,
                table_level,
                region_entry,
                &region_next_addr);

        void __phys *map_next_addr;
        paging_entry_read_addr(
                mode,
                table_level,
                map_entry,
                &map_next_addr);

        // They are both tables
        if(!(map_entry_flags & PAGING_ENTRY_SHARED))
        {
            // the map entry points to some other region's page table
            void __phys *shared_table;
            res = page_alloc(ptr_orderof(level_below_size), &shared_table, 0);
            if(res)
            {
                return -ENOMEM;
            }

            // Make a copy of the other region's top level table
            memcpy((void *)__va(shared_table),
                   (void *)__va(map_next_addr),
                   level_below_size);

            // Create a shared table entry
            res = create_shared_pt_table_entry(
                    mode,
                    map_entry,
                    table_level,
                    shared_table);
            if(res)
            {
                return res;
            }
        }

        paging_entry_read_addr(
                mode,
                table_level,
                map_entry,
                &map_next_addr);

        // Already was or is now a shared page,
        // so we can recursively call ourselves on it
        res = map_region_tables(mode,
                                map_next_addr,
                                region_next_addr,
                                table_level - 1,
                                vbase + (entry_region_size * (vi - vindex)),
                                map,
                                region);

        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
free_page_tables(
        const struct paging_mode *mode,
        void __phys *table,
        int level)
{
    int res;

    void *table_entries = (void *)__va(table);
    size_t num_entries = paging_level_num_entries(mode, level);
    size_t entry_size = paging_level_entry_size(mode, level);

    for(size_t i = 0; i < num_entries; i++)
    {
        void *entry = table_entries + (i * entry_size);
        unsigned long entry_flags;
        res = paging_entry_get_flags(
                mode,
                level,
                entry,
                &entry_flags);
        if(res) {
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

        DEBUG_ASSERT(entry_flags & PAGING_ENTRY_IS_TABLE);

        // This must be a present table
        void __phys *subtable;
        res = paging_entry_read_addr(
                mode,
                level,
                entry,
                &subtable);
        if(res) {
            wprintk("free_page_tables: failed to get entry subtable address!\n");
            return res;
        }

        res = free_page_tables(mode, subtable, level - 1);
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

// This region should not exist in any maps at this point
int
arch_vmem_region_deinit(struct vmem_region *region)
{
    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    struct vmem_region_paging_state *pt_state;
    pt_state = vmem_region_get_paging_state(region);

    if(pt_state->entry_only)
    {
        return 0;
    }
    else
    {
        return free_page_tables(
                mode,
                pt_state->pt_table,
                pt_state->pt_level);
    }
}

int
arch_vmem_map_map_region(
        struct vmem_map *map,
        struct vmem_region_ref *ref)
{
    int res;

    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    struct vmem_map_paging_state *map_state;
    map_state = vmem_map_get_paging_state(map);

    struct vmem_region_paging_state *region_state;
    region_state = vmem_region_get_paging_state(ref->region);

    int pt_level = map_state->pt_level;

    uint64_t *map_entry = NULL;
    void __phys *map_table = map_state->pt_root;
    void __phys *region_table = region_state->pt_table;

    if(pt_level < region_state->pt_level)
    {
        eprintk("arch_vmem_map_map_region: invalid map->pt_level < "
                "region->pt_level (%d < %d)\n",
                (int)pt_level,
                (int)region_state->pt_level);
        return -EINVAL;
    }

    map_table = map_state->pt_root;
    while(pt_level > region_state->pt_level)
    {

        size_t index = paging_level_addr_table_index(
                mode,
                pt_level,
                ref->virt_addr);
        size_t entry_size = paging_level_entry_size(
                mode,
                pt_level);
        map_entry = ((void*)__va(map_table)) + (index * entry_size);

        order_t next_table_order;
        uint64_t present_mask;
        uint64_t shared_mask;

        next_table_order = paging_level_table_order(mode, pt_level - 1);

        unsigned long map_entry_flags;
        paging_entry_get_flags(
                mode,
                pt_level,
                map_entry,
                &map_entry_flags);

        if(map_entry_flags & PAGING_ENTRY_PRESENT)
        {
            if(map_entry_flags & PAGING_ENTRY_SHARED)
            {
                paging_entry_read_addr(
                        mode,
                        pt_level,
                        map_entry,
                        &map_table);
            }
            else
            {
                // the map entry points to some other region's page
                // table

                void __phys *shared_table;
                res = page_alloc(next_table_order, &shared_table, 0);
                if(res)
                {
                    return -ENOMEM;
                }

                // Make a copy of the other region's top level
                // table
                paging_entry_read_addr(
                        mode,
                        pt_level,
                        map_entry,
                        &map_table);
                memcpy((void *)__va(shared_table),
                       (void *)__va(map_table),
                       1ULL<<next_table_order);

                // Create a shared table entry
                res = create_shared_pt_table_entry(
                        mode,
                        map_entry,
                        pt_level,
                        shared_table);
                if(res)
                {
                    return res;
                }

                map_table = shared_table;
            }
        }
        else
        {
            void __phys *shared_table;
            res = page_alloc(next_table_order, &shared_table, 0);
            if(res)
            {
                return -ENOMEM;
            }
            memset((void *)__va(shared_table), 0, 1ULL<<next_table_order);

            // Create a shared table entry
            res =
                create_shared_pt_table_entry(
                        mode,
                        map_entry,
                        pt_level,
                        shared_table);
            if(res)
            {
                return res;
            }

            map_table = shared_table;
        }

        pt_level--;
    }

    if(region_state->entry_only)
    {
        size_t index;
        index = paging_level_addr_table_index(
                mode,
                pt_level,
                ref->virt_addr);
        size_t entry_size;
        entry_size = paging_level_entry_size(
                mode,
                pt_level);

        void *entry = ((void*)__va(map_table)) + (index * entry_size);

        int can_be_leaf = paging_level_can_be_leaf(mode, pt_level);
        if(!can_be_leaf)
        {
            eprintk("Tried mapping entry_only region with invalid "
                    "pt_level (%d)\n",
                    pt_level);
            return -EINVAL;
        }

        unsigned long entry_flags;
        paging_entry_get_flags(
                mode,
                pt_level,
                entry,
                &entry_flags);

        if(entry_flags & PAGING_ENTRY_PRESENT)
        {
            eprintk("Tried mapping entry_only vmem_region with unexpected "
                    "overlap!\n");
            return -EINVAL;
        }

        DEBUG_ASSERT(PAGING_PT_ENTRY_BUFLEN >= entry_size);
        memcpy(entry,
               region_state->pt_entry_buffer,
               entry_size);
    }
    else
    {
        res = map_region_tables(mode,
                                map_table,
                                region_table,
                                pt_level,
                                ref->virt_addr,
                                map,
                                ref->region);
        if(res)
        {
            return res;
        }
    }

    return 0;
}

static int
unmap_region_tables(
        const struct paging_mode *mode,
        void __phys *map_table,
        void __phys *region_table,
        int table_level,
        void *vbase)
{
    int res;

    size_t entry_size;
    size_t entry_region_size;
    size_t num_possible_entries;
    size_t vindex;

    size_t level_below_entry_size;
    order_t level_below_table_order;
    size_t level_below_num_possible_entries;

    entry_size = paging_level_entry_size(mode, table_level);
    entry_region_size = paging_level_entry_region_size(mode, table_level);
    num_possible_entries = paging_level_num_entries(mode, table_level);
    vindex = paging_level_addr_table_index(
            mode,
            table_level,
            vbase);

    if(table_level == 0) {
        level_below_table_order = 0;
        level_below_num_possible_entries = 0;
        level_below_entry_size = 0;
    } else {
        level_below_table_order = paging_level_table_order(mode, table_level-1);
        level_below_num_possible_entries = paging_level_num_entries(mode, table_level-1);
        level_below_entry_size = paging_level_entry_size(mode, table_level-1);
    }

    for(size_t vi = vindex; vi < num_possible_entries; vi++)
    {
        void *map_entry = ((void*)__va(map_table)) + (vi * entry_size);
        void *region_entry = ((void*)__va(region_table)) + ((vi - vindex) * entry_size);

        unsigned long region_entry_flags;
        paging_entry_get_flags(
                mode,
                table_level,
                region_entry,
                &region_entry_flags);

        if(!(region_entry_flags & PAGING_ENTRY_PRESENT))
        {
            // Region isn't present, so this is the end of the region
            break;
        }

        unsigned long map_entry_flags;
        paging_entry_get_flags(
                mode,
                table_level,
                map_entry,
                &map_entry_flags);

        int map_is_leaf = map_entry_flags & PAGING_ENTRY_IS_LEAF;
        int region_is_leaf = region_entry_flags & PAGING_ENTRY_IS_LEAF;

        if(map_is_leaf != region_is_leaf)
        {
            eprintk("unmap_region_tables: map_is_leaf != "
                    "region_is_leaf\n");
            return -EINVAL;
        }
        else if(map_is_leaf /* && region_is_leaf */)
        {
            // Zero out the entry in the map
            paging_entry_clear(
                    mode,
                    table_level,
                    map_entry);
        }
        else
        {
            // They are both tables
            DEBUG_ASSERT((region_entry_flags & PAGING_ENTRY_IS_TABLE)
                      && (map_entry_flags & PAGING_ENTRY_IS_TABLE));

            void __phys *map_next_addr;
            paging_entry_read_addr(
                    mode,
                    table_level,
                    map_entry,
                    &map_next_addr);

            void __phys *region_next_addr;
            paging_entry_read_addr(
                    mode,
                    table_level,
                    region_entry,
                    &region_next_addr);

            if(map_next_addr == region_next_addr)
            {
                // The region owns this page
                paging_entry_clear(mode, table_level, map_entry);
            }
            else
            {
                // This is a shared page
                res = unmap_region_tables(
                    mode,
                    map_next_addr,
                    region_next_addr,
                    table_level - 1,
                    vbase + (entry_region_size * (vi - vindex)));
                if(res)
                {
                    eprintk("Failed to unmap vmem region subtable "
                            "(Possible "
                            "Physical Memory Leak)! (err=%s)\n",
                            errnostr(res));
                    continue;
                }
                // Check if the shared table is now empty
                int can_free_table = 1;
                for(size_t below = 0; below < level_below_num_possible_entries;
                    below++)
                {
                    void *below_entry;
                    below_entry = ((void*)__va(map_next_addr))
                                + (below * level_below_entry_size);

                    unsigned long below_flags;
                    paging_entry_get_flags(
                            mode,
                            table_level-1,
                            below_entry,
                            &below_flags);

                    if(below_flags & PAGING_ENTRY_PRESENT)
                    {
                        can_free_table = 0;
                        break;
                    }
                }
                if(can_free_table)
                {
                    // Free the shared table if it's now empty
                    page_free(level_below_table_order, map_next_addr);
                    paging_entry_clear(
                            mode,
                            table_level,
                            map_entry);
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

    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    struct vmem_map_paging_state *map_state;
    map_state = vmem_map_get_paging_state(map);
    struct vmem_region_paging_state *region_state;
    region_state = vmem_region_get_paging_state(ref->region);

    int pt_level = map_state->pt_level;

    void __phys *map_table = map_state->pt_root;
    void __phys *region_table = region_state->pt_table;

    if(pt_level < region_state->pt_level)
    {
        eprintk("arch_vmem_map_unmap_region: map->pt_level < region->pt_level "
                "(%d < %d)\n",
                pt_level,
                region_state->pt_level);
        return -EINVAL;
    }

    while(pt_level > region_state->pt_level)
    {
        size_t index =
            paging_level_addr_table_index(
                    mode,
                    pt_level,
                    ref->virt_addr);
        size_t entry_size = paging_level_entry_size(mode, pt_level);
        void *map_entry = ((void *)__va(map_table)) + (index * entry_size);

        unsigned long map_entry_flags;
        paging_entry_get_flags(
                mode,
                pt_level,
                map_entry,
                &map_entry_flags);

        if(!(map_entry_flags & PAGING_ENTRY_PRESENT))
        {
            eprintk("arch_vmem_map_unmap_region: found not-present "
                    "page table "
                    "in region!\n");
            return -EINVAL;
        }

        DEBUG_ASSERT(map_entry_flags & PAGING_ENTRY_IS_TABLE);

        void __phys *next_table_addr;
        paging_entry_read_addr(
                mode,
                pt_level,
                map_entry,
                &next_table_addr);

        map_table = next_table_addr;
        pt_level--;
    }

    size_t entry_size = paging_level_entry_size(
            mode,
            pt_level);

    if(region_state->entry_only)
    {
        size_t index =
            paging_level_addr_table_index(
                mode,
                pt_level,
                ref->virt_addr);

        void *entry = ((void*)__va(map_table)) + (index * entry_size);

        unsigned long entry_flags;
        paging_entry_get_flags(
                mode,
                pt_level,
                entry,
                &entry_flags);

        if((!(entry_flags & PAGING_ENTRY_PRESENT))
         ||(!(entry_flags & PAGING_ENTRY_IS_LEAF))) {
            eprintk("Found not-present page when unmapping "
                    "entry_only "
                    "vmem_region!\n");
            return -EINVAL;
        }
    }
    else
    {
        res = unmap_region_tables(
                mode,
                map_table,
                region_table,
                pt_level,
                ref->virt_addr);
        if(res)
        {
            return res;
        }
    }

    if(pt_level != map_state->pt_level)
    {
        // TODO check if the top level directory is now empty,
        // and free completely "not-present" intermediate tables
        dprintk("WARNING: Not checking for pointless intermediate"
                " page tables on region unmapping."
                " (could be wasting memory)\n");
    }

    return 0;
}

int
arch_vmem_paged_region_map(struct vmem_region *region,
                           size_t offset,
                           void __phys *phys_addr,
                           size_t size,
                           unsigned long flags)
{
    int res;

    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    dprintk("arch_vmem_paged_region_map(\n"
            "\tregion=%p\n"
            "\toffset=%p\n"
            "\tphys_addr=%p\n"
            "\tsize=%p\n"
            "\tflags=%p\n",
            (uintptr_t)region,
            (uintptr_t)offset,
            (uintptr_t)phys_addr,
            (uintptr_t)size,
            (uintptr_t)flags);

    DEBUG_ASSERT(KERNEL_ADDR(region));

    size_t min_region_size = paging_level_entry_region_size(mode, 0);

    if((offset % min_region_size)|| (size % min_region_size))
    {
        eprintk("Cannot map paged area offsets: [%p - %p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(offset),
                (uintptr_t)(offset + size));
        return -EINVAL;
    }

    if((uintptr_t)phys_addr % min_region_size)
    {
        eprintk("Cannot map paged area to physical address (%p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(phys_addr));
        return -EINVAL;
    }

    struct vmem_region_paging_state *region_state;
    region_state = vmem_region_get_paging_state(region);

    while(size > 0)
    {
        int max_entry_level = region_state->paged_max_entry_level;

        int entry_level = -1;
        size_t entries_per_table;
        size_t page_size;

        for(int level = paging_mode_num_levels(mode)-1;
                level >= 0;
                level--)
        {
            size_t entry_region_size =
                paging_level_entry_region_size(mode, level);
            if(size >= entry_region_size &&
               (((uintptr_t)phys_addr % entry_region_size) == 0) &&
               (((uintptr_t)offset % entry_region_size) == 0) &&
               (max_entry_level >= level))
            {
                entry_level = level;
                page_size = entry_region_size;
                entries_per_table = paging_level_num_entries(mode, level);
                break;
            }
        }

        if(entry_level < 0) {
            // We failed a check we should have already passed,
            // something screw-y is going on with our memory (PANIC!)
            panic("End of paged region mapping is misaligned (even "
                  "though we "
                  "passed this check at the beginning of "
                  "\"arch_vmem_paged_region_map\"!");
        }

        // Drill the mapping

        void __phys *cur_table = region_state->pt_table;
        int cur_level = region_state->pt_level;

        do
        {
            size_t cur_region_size = paging_level_entry_region_size(
                    mode,
                    cur_level);
            size_t cur_entry_size = paging_level_entry_size(
                    mode,
                    cur_level);
            size_t cur_entries_per_table =
                paging_level_num_entries(mode, cur_level);

            size_t cur_index =
                (offset / cur_region_size) % cur_entries_per_table;

            void *cur_entry = ((void*)__va(cur_table))
                            + (cur_index * cur_entry_size);

            unsigned long cur_entry_flags;
            paging_entry_get_flags(
                    mode,
                    cur_level,
                    cur_entry,
                    &cur_entry_flags);

            if(cur_entry_flags & PAGING_ENTRY_PRESENT)
            {
                // This must be a page table
                DEBUG_ASSERT(cur_entry_flags & PAGING_ENTRY_IS_TABLE);

                void __phys *next_table_addr;
                paging_entry_read_addr(
                        mode,
                        cur_level,
                        cur_entry,
                        &next_table_addr);

                cur_table = next_table_addr;

                DEBUG_ASSERT_MSG(KERNEL_ADDR((void *)__va(cur_table)),
                                 "table paddr=%p, vaddr=%p",
                                 (void *)cur_table,
                                 (void *)__va(cur_table));

                cur_level--;
            }
            else
            {
                // The entry isn't present
                void __phys *subtable;
                res = create_empty_pt_table(
                        mode,
                        &subtable,
                        cur_level - 1);
                if(res)
                {
                    return res;
                }

                DEBUG_ASSERT(KERNEL_ADDR((void *)__va(subtable)));

                res = create_permissive_pt_table_entry(
                        mode,
                        cur_entry,
                        cur_level,
                        subtable);
                if(res)
                {
                    return res;
                }

                cur_table = subtable;
                cur_level--;
            }
        } while(cur_level != entry_level);

        // We should be on the correct level
        size_t index = (offset / page_size) % entries_per_table;
        size_t cur_entry_size = paging_level_entry_size(mode, cur_level);
        uint64_t *entry = ((void *)__va(cur_table)) + (index * cur_entry_size);

        dprintk("Creating PT Leaf Entry at Level %d, Index %d [Region "
                "Level %d]\n",
                (int)cur_level,
                (int)index,
                region-state->pt_level);

        res = create_pt_leaf_entry(
                mode,
                entry,
                entry_level,
                phys_addr,
                flags);
        if(res)
        {
            wprintk("Failed to create pt_leaf_entry!\n");
            return res;
        }

        offset += page_size;
        phys_addr += page_size;
        size -= page_size;
    }
    return 0;
}

// WORKING

int
arch_vmem_paged_region_unmap(struct vmem_region *region,
                             size_t offset,
                             size_t size)
{
    int res;

    const struct paging_mode *mode = arch_paging_mode();
    DEBUG_ASSERT(mode != NULL);

    struct vmem_region_paging_state *region_state =
        vmem_region_get_paging_state(region);

    size_t min_region_size;
    min_region_size = paging_level_entry_region_size(mode, 0);

    if((offset % min_region_size) || (size % min_region_size))
    {
        eprintk("Cannot map paged area offsets: [%p - %p)"
                " (No page size small enough to align)\n",
                (uintptr_t)(offset),
                (uintptr_t)(offset + size));
        return -EINVAL;
    }

    while(size > 0)
    {
        int max_entry_level = region_state->pt_level - 1;

        size_t entries_per_table;
        size_t page_size;
        int entry_level = -1;

        for(int level = paging_mode_num_levels(mode)-1;
                level >= 0;
                level--)
        {
            size_t entry_region_size = paging_level_entry_region_size(mode, level);
            if((size >= entry_region_size) &&
               ((offset % entry_region_size )== 0) &&
               (max_entry_level >= level))
            {
                page_size = entry_region_size;
                entries_per_table = paging_level_num_entries(mode, level);
                entry_level = level;
                break;
            }
        }

        if(entry_level < 0)
        {
            // We failed a check we should have already passed,
            // something screw-y is going on with our memory (PANIC!)
            panic("End of paged region mapping is misaligned (even "
                  "though we "
                  "passed this check at the beginning of "
                  "\"arch_vmem_paged_region_map\"!");
        }

        // Drill the mapping

        void __phys *cur_table = region_state->pt_table;
        int cur_level = region_state->pt_level;

        do
        {
            size_t cur_region_size = paging_level_entry_region_size(mode, cur_level);
            size_t cur_entry_size = paging_level_entry_size(mode, cur_level);
            size_t cur_entries_per_table =
                paging_level_num_entries(mode, cur_level);
            size_t cur_index =
                (offset / cur_region_size) % cur_entries_per_table;

            void *cur_entry = ((void *)__va(cur_table)) + (cur_index * cur_entry_size);

            DEBUG_ASSERT(KERNEL_ADDR(cur_entry));

            unsigned long cur_entry_flags;
            paging_entry_get_flags(
                    mode,
                    cur_level,
                    cur_entry,
                    &cur_entry_flags);

            if(cur_entry_flags & PAGING_ENTRY_PRESENT)
            {
                // This must be a page table
                DEBUG_ASSERT(cur_entry_flags & PAGING_ENTRY_IS_TABLE);

                void __phys *next_table_addr;
                paging_entry_read_addr(
                        mode,
                        cur_level,
                        cur_entry,
                        &next_table_addr);

                cur_table = next_table_addr;
                cur_level--;
            }
            else
            {
                // The entry isn't present
                void __phys *subtable;
                res = create_empty_pt_table(
                        mode,
                        &subtable,
                        cur_level - 1);
                if(res)
                {
                    return res;
                }

                DEBUG_ASSERT(KERNEL_ADDR((void *)__va(subtable)));

                res = create_permissive_pt_table_entry(
                        mode,
                        cur_entry,
                        cur_level,
                        subtable);
                if(res)
                {
                    return res;
                }

                cur_table = subtable;
                cur_level--;
            }
        } while(cur_level != entry_level);

        // We should be on the correct level
        size_t index = (offset / page_size) % entries_per_table;
        size_t cur_entry_size = paging_level_entry_size(mode, cur_level);
        void *entry = ((void*)__va(cur_table)) + (index * cur_entry_size);

        // Unmap the entry fully
        paging_entry_clear(mode, cur_level, entry);

        offset += page_size;
        size -= page_size;
    }

    return 0;
}

static int
dump_page_table(
        printk_f *printer,
        const struct paging_mode *mode,
        void __phys *table_phys_addr,
        int level,
        void *virt_base,
        int is_root)
{
    int res = 0;

    int num_levels = paging_mode_num_levels(mode);

    if(level >= num_levels || level <= 0)
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
        (*printer)("%p -> %p [size=0x%llx]\n",                                 \
                   pending_vaddr,                                              \
                   pending_paddr,                                              \
                   (ull_t)pending_size);                                       \
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
        paging_entry_read_addr(mode, level, entry, &addr);

        unsigned long flags;
        paging_entry_get_flags(mode, level, entry, &flags);

        if(!(flags & PAGING_ENTRY_PRESENT))
        {
            // Not Present, continue.
            virt_base += entry_region_size;
            continue;
        }

        int is_leaf = flags & PAGING_ENTRY_IS_LEAF;

        if(leaf_pending)
        {
            if(!is_leaf)
            {
                // Dump the pending leaf because we are going down
                // a level
                leaf_pending = 0;
                DUMP_PENDING_LEAF();
            }
            else if(flags != pending_flags || addr != pending_next_paddr)
            {
                // Dump the pending leaf because some flag or
                // address changed
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
            (*printer)("[level(%d) index(%d)] ", level, entry_index);
            uint64_t shared_mask;
            (*printer)("Table %s\n", flags & PAGING_ENTRY_SHARED ? "[SHARED]" : "");
            res = dump_page_table(printer, mode, addr, level - 1, virt_base, 0);
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
arch_vmem_map_activate(struct vmem_map *map)
{
    DEBUG_ASSERT(KERNEL_ADDR(map));

    const struct paging_mode *mode = arch_paging_mode();

    struct vmem_map_paging_state *state =
        vmem_map_get_paging_state(map);

    return arch_paging_set_pt_root(state->pt_root);
}

static void
tlb_shootdown_xcall(void *with_pt_root_phys)
{
    // Disable IRQs to make absolutely sure we can't change the
    // value of cr3 by accident
    int irq_flags = disable_save_irqs();

    void __phys *pt_root = (void __phys *)with_pt_root_phys;
    arch_paging_flush_tlb(pt_root, 0);

    enable_restore_irqs(irq_flags);
}


int
arch_vmem_map_flush(struct vmem_map *map)
{
    if(map->active_on <= 0)
    {
        return 0;
    }

    if((map->active_on == 1) && map == vmem_map_get_current())
    {
        arch_paging_flush_tlb(NULL, 1);
        return 0;
    }

    struct vmem_map_paging_state *map_state;
    map_state = vmem_map_get_paging_state(map);

    int res =
        xcall_broadcast(tlb_shootdown_xcall, (void *)map_state->pt_root);
    if(res)
    {
        return res;
    }

    return 0;
}

void
arch_dump_vmem_map(printk_f *printer, struct vmem_map *map)
{
    const struct paging_mode *mode = arch_paging_mode();
    struct vmem_map_paging_state *map_state =
        vmem_map_get_paging_state(map);
    void __phys *root = map_state->pt_root;
    (*printer)("--- Virtual Memory Mapping (Root Level = %d) ---\n",
               map_state->pt_level);
    int res = dump_page_table(printer,
                              mode,
                              map_state->pt_root,
                              map_state->pt_level,
                              0x0,
                              1);
    if(res)
    {
        (*printer)("[[[ An Error Occurred When Printing Virtual Memory Mapping "
                   "(err=%s)\n",
                   errnostr(res));
    }
    (*printer)("----------------------------------------------------\n");
}

// init/deinit
int
arch_vmem_map_init(struct vmem_map *map)
{
    int res;

    const struct paging_mode *mode;
    mode = arch_paging_mode();

    int num_levels = paging_mode_num_levels(mode);

    struct vmem_map_paging_state *map_state;
    map_state = vmem_map_get_paging_state(map);

    map_state->pt_level = 0;

    order_t root_order = paging_level_table_order(mode, num_levels-1);

    res = page_alloc(
            root_order,
            &map_state->pt_root,
            0);
    if(res)
    {
        return res;
    }

    map_state->pt_level = num_levels-1;
    memset((void *)__va(map_state->pt_root), 0, 1ULL<<root_order);

    return 0;
}

// Every region should have been unmapped from this map already
int
arch_vmem_map_deinit(struct vmem_map *map)
{
    int res;

    const struct paging_mode *mode;
    mode = arch_paging_mode();

    int num_levels = paging_mode_num_levels(mode);

    struct vmem_map_paging_state *map_state;
    map_state = vmem_map_get_paging_state(map);

    int root_level = map_state->pt_level;
    order_t root_order = paging_level_table_order(mode, root_level);

    res = page_free(root_order, map_state->pt_root);
    if(res)
    {
        return res;
    }

    return 0;
}

