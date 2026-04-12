#ifndef __KANAWHA__PAGING_PAGING_H__
#define __KANAWHA__PAGING_PAGING_H__

#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/pointer.h>

struct vmem_map;
struct vmem_region;

/*
 * This is an abstraction for page tables
 * on most modern architectures
 */

struct paging_mode
{
    unsigned int num_levels;

    // how many table entries at this level?
    // (len=num_levels)
    const order_t *level_num_entries_order;

    // how many bytes per-entry in the table?
    // (len=num_levels)
    const order_t *level_entry_order;

    // how big is the region of virt/phys?
    // memory that an entry in this region
    // would refer to?
    // (len=num_levels)
    const order_t *level_entry_region_order;

    // Assorted single bit flags about this level
#define PAGING_LEVEL_FLAG_CAN_BE_LEAF  (1ULL<<0)
    const unsigned long *level_flags;

    // Functional fields
    size_t(* const level_addr_table_index)(int level, void *addr);

#define PAGING_ENTRY_PRESENT       (1ULL<<0)
#define PAGING_ENTRY_IS_LEAF       (1ULL<<1)
#define PAGING_ENTRY_IS_TABLE      (1ULL<<2)
#define PAGING_ENTRY_SHARED        (1ULL<<3)
#define PAGING_ENTRY_READABLE      (1ULL<<4)
#define PAGING_ENTRY_WRITEABLE     (1ULL<<5)
#define PAGING_ENTRY_EXECUTABLE    (1ULL<<6)
#define PAGING_ENTRY_USER_ACCESS   (1ULL<<7)
#define PAGING_ENTRY_KERNEL_ACCESS (1ULL<<8)
#define PAGING_ENTRY_CACHE_DISABLE (1ULL<<9)

#define PAGING_ENTRY_FLAGS_ALL ((1ULL<<8)-1)
    int(* const get_entry_flags)(int level, void *entry_data, unsigned long *flags);
    int(* const set_entry_flags)(int level, void *entry_data, unsigned long flags);
    int(* const clear_entry_flags)(int level, void *entry_data, unsigned long flags);

    int(* const clear_entry)(int level, void *entry_data);

    int(* const read_entry_addr)(int level, void *entry_data, void __phys **addr);
    int(* const write_entry_addr)(int level, void *entry_data, void __phys *addr);
};

static inline int
dump_paging_entry_flags(
        printk_f *printer,
        unsigned long flags)
{
    if(flags & PAGING_ENTRY_PRESENT) {
        (*printer)("[PRESENT]");
    }
    if(flags & PAGING_ENTRY_IS_LEAF) {
        (*printer)("[LEAF]");
    }
    if(flags & PAGING_ENTRY_IS_TABLE) {
        (*printer)("[TABLE]");
    }
    if(flags & PAGING_ENTRY_SHARED) {
        (*printer)("[SHARED]");
    }
    if(flags & PAGING_ENTRY_READABLE) {
        (*printer)("[READABLE]");
    }
    if(flags & PAGING_ENTRY_WRITEABLE) {
        (*printer)("[WRITEABLE]");
    }
    if(flags & PAGING_ENTRY_EXECUTABLE) {
        (*printer)("[EXECUTABLE]");
    }
    if(flags & PAGING_ENTRY_USER_ACCESS) {
        (*printer)("[USER_ACCESS]");
    }
    if(flags & PAGING_ENTRY_KERNEL_ACCESS) {
        (*printer)("[KERNEL_ACCESS]");
    }
    if(flags & PAGING_ENTRY_CACHE_DISABLE) {
        (*printer)("[CACHE_DISABLE]");
    }
    return 0;
}

#define PAGING_PT_ENTRY_BUFLEN (8)

struct vmem_region_paging_state
{
    int pt_level;

    int entry_only;
    uint8_t pt_entry_buffer[PAGING_PT_ENTRY_BUFLEN];

    int paged_max_entry_level;

    void __phys *pt_table;
};
struct vmem_map_paging_state
{
    int pt_level;
    void __phys *pt_root;
};


// To be implemented by any architecture which
// makes use of this subsystem.

extern const struct paging_mode *
arch_paging_mode(void);

#ifdef CONFIG_VMEM_VIA_PAGING
extern struct vmem_map_paging_state *
arch_get_vmem_map_paging_state(
        struct vmem_map *map);

extern struct vmem_region_paging_state *
arch_get_vmem_region_paging_state(
        struct vmem_region *map);

extern int
arch_paging_set_pt_root(
        void __phys *pt_root,
        int root_level);

extern int
arch_paging_flush_tlb(
        void __phys *cond_pt_root,
        int force);
#endif /* CONFIG_VMEM_VIA_PAGING */

// Helper functions
static inline unsigned int
paging_mode_num_levels(
        const struct paging_mode *mode)
{
    return mode->num_levels;
}

static inline order_t
paging_level_num_entries_order(
        const struct paging_mode *mode,
        int level)
{
    DEBUG_ASSERT(level < mode->num_levels);
    return mode->level_num_entries_order[level];
}

static inline size_t
paging_level_num_entries(
        const struct paging_mode *mode,
        int level)
{
    return 1ULL<<paging_level_num_entries_order(mode, level);
}

static inline order_t
paging_level_entry_order(
        const struct paging_mode *mode,
        int level)
{
    DEBUG_ASSERT(level < mode->num_levels);
    return mode->level_entry_order[level];
}
static inline size_t
paging_level_entry_size(
        const struct paging_mode *mode,
        int level)
{
    return 1ULL<<paging_level_entry_order(mode, level);
}

static inline order_t
paging_level_table_order(
        const struct paging_mode *mode,
        int level)
{
    order_t num_order = paging_level_num_entries_order(mode, level);
    order_t entry_order = paging_level_entry_order(mode, level);
    return num_order + entry_order;
}
static inline size_t
paging_level_table_size(
        const struct paging_mode *mode,
        int level)
{
    return 1ULL<<paging_level_table_order(mode, level);
}

static inline order_t
paging_level_entry_region_order(
        const struct paging_mode *mode,
        int level)
{
    DEBUG_ASSERT(level < mode->num_levels);
    return mode->level_entry_region_order[level];
}

static inline size_t
paging_level_entry_region_size(
        const struct paging_mode *mode,
        int level)
{
    return 1ULL<<paging_level_entry_region_order(mode, level);
}

static inline order_t
paging_level_table_region_order(
        const struct paging_mode *mode,
        int level)
{
    order_t entry_order = paging_level_entry_region_order(mode, level);
    order_t num_entries_order = paging_level_num_entries_order(mode, level);
    return entry_order + num_entries_order;
}

static inline size_t
paging_level_table_region_size(
        const struct paging_mode *mode,
        int level)
{
    return 1ULL<<paging_level_table_region_order(mode, level);
}

static inline int
paging_level_can_be_leaf(
        const struct paging_mode *mode,
        int level)
{
    DEBUG_ASSERT(level < mode->num_levels);
    return mode->level_flags[level] & PAGING_LEVEL_FLAG_CAN_BE_LEAF;
}

static inline size_t
paging_level_addr_table_index(
        const struct paging_mode *mode,
        int level,
        void *addr)
{
    DEBUG_ASSERT(KERNEL_ADDR(mode->level_addr_table_index));
    return (*mode->level_addr_table_index)(level, addr);
}

static inline int 
paging_entry_get_flags(
        const struct paging_mode *mode,
        int level,
        void *entry,
        unsigned long *flags)
{
    return (*mode->get_entry_flags)(
            level,
            entry,
            flags);
}

static inline int
paging_entry_set_flags(
        const struct paging_mode *mode,
        int level,
        void *entry,
        unsigned long flags)
{
    return (*mode->set_entry_flags)(
            level,
            entry,
            flags);
}

static inline int
paging_entry_clear_flags(
        const struct paging_mode *mode,
        int level,
        void *entry,
        unsigned long flags)
{
    return (*mode->clear_entry_flags)(
            level,
            entry,
            flags);
}

static inline int 
paging_entry_read_addr(
        const struct paging_mode *mode,
        int level,
        void *entry,
        void __phys **addr)
{
    return (*mode->read_entry_addr)(
            level,
            entry,
            addr);
}

static inline int
paging_entry_write_addr(
        const struct paging_mode *mode,
        int level,
        void *entry,
        void __phys *addr)
{
    return (*mode->write_entry_addr)(
            level,
            entry,
            addr);
}

static inline int
paging_entry_clear(
        const struct paging_mode *mode,
        int level,
        void *entry_data)
{
    return (*mode->clear_entry)(level, entry_data);
}

#endif
