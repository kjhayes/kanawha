#ifndef __KANAWHA__PAGING_PAGE_TABLE_H__
#define __KANAWHA__PAGING_PAGE_TABLE_H__

#include <kanawha/paging/paging.h>
#include <kanawha/pointer.h>

struct pagetable
{
    int root_level;
    int max_leaf_level;
    int min_map_level;

    order_t root_table_order;
    void __phys *root_table;
};

int
pagetable_init(
        struct pagetable *pt,
        int root_level,
        int max_leaf_level,
        int min_map_level,
        unsigned long flags);
int
pagetable_deinit(
        struct pagetable *table);

// Helpers
int
pagetable_root_level(
        struct pagetable *pt);
void __phys *
pagetable_root(
        struct pagetable *pt);
order_t
pagetable_virt_order(
        struct pagetable *pt);

int
pagetable_walk_leaf(
        struct pagetable *pt,
        void *vaddr,
        void __phys **page_out,
        order_t *page_order_out,
        unsigned long *entry_flags_out);

// Drill a mapping from this page table to physical memory
int
pagetable_drill(
        struct pagetable *pt,
        void *vaddr,
        void __phys *phys,
        size_t size,
        unsigned long entry_flags);

// Clear the mapping at [vaddr,vaddr+size)
// which was previously drilled by "pagetable_drill".
// (I don't like this name but it is consistent -KJH)
int
pagetable_undrill(
        struct pagetable *pt,
        void *vaddr,
        size_t size);

// Map child onto parent at address "vaddr"
int
pagetable_map(
        struct pagetable *parent,
        struct pagetable *child,
        void *vaddr,
        size_t size);

// This region "[vaddr,vaddr+size)" should
// have previously been mapped with "pagetable_map"
int
pagetable_unmap(
        struct pagetable *pt,
        void *vaddr,
        size_t size);

int
pagetable_dump(
        printk_f *printer,
        struct pagetable *pt);

#endif
