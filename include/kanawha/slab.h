#ifndef __KANAWHA__SLAB_H__
#define __KANAWHA__SLAB_H__

#include <kanawha/list.h>

/*
 * Kanawha Kernel "Slab" allocator framework
 *
 * Slab allocators in Kanawha are restricted allocators
 * that are setup to handle a few cases where regular allocators
 * such as "page_alloc" or "kmalloc" might not be use-able.
 *
 * - Each allocator can only allocate a fixed size objects
 * - An allocator only depends on large block allocations being available underneath it,
 *   either statically allocated in .bss or from the "page_alloc" framework
 *
 * This means we can "boot-strap" allocators such as "page_alloc" by providing some statically allocated
 * memory for it during boot. And that we can use slab allocators to allocate smaller than page sized
 * objects for internal use in "kmalloc" safely.
 *ynam
 * Because of the constrained use-cases of the slab allocator framework here, it should be used
 * when needed. It is designed to be useful even very early during boot, and as such can be fairly slow.
 */

struct slab_allocator {
    struct ilist_head block_list;
    void *inline_block_base;
    size_t inline_block_size;
    size_t obj_size;
    order_t obj_align;
};

#define SLAB_ALLOC_BLOCK_STATIC (1UL<<0)

struct slab_alloc_block {
    ilist_node_t list_node;
    unsigned long flags;
    void *block_base;
    size_t block_size;
    size_t num_slots;
    size_t num_free;
    unsigned long *bitmap;
    void *objects;
};

struct slab_allocator *
create_static_slab_allocator(
        void *buffer,
        size_t buffer_size,
        size_t obj_size,
        order_t obj_align);

// Relies on page_alloc being up
struct slab_allocator *
create_dynamic_slab_allocator(
        size_t obj_size,
        order_t obj_align);

void * slab_alloc(struct slab_allocator *alloc);
void slab_free(struct slab_allocator *alloc, void *obj);

size_t slab_objs_free(struct slab_allocator *alloc);
size_t slab_objs_alloc(struct slab_allocator *alloc);
size_t slab_objs_total(struct slab_allocator *alloc);

#endif
