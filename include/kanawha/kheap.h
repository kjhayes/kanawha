#ifndef __KANAWHA__KHEAP_H__
#define __KANAWHA__KHEAP_H__

#include <kanawha/buddy.h>
#include <kanawha/errno.h>
#include <kanawha/export.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/slab.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

// #define KHEAP_SLAB_XLIST(X, ...)                                               \
//     X(1, 0)                                                                    \
//     X(2, 1)                                                                    \
//     X(4, 2)                                                                    \
//     X(8, 2)                                                                    \
//     X(8, 3)                                                                    \
//     X(12, 2)                                                                   \
//     X(16, 4)                                                                   \
//     X(24, 3)                                                                   \
//     X(32, 4)                                                                   \
//     X(48, 4)                                                                   \
//     X(64, 4)                                                                   \
//     X(96, 4)                                                                   \
//     X(128, 4)
// 
// enum
// {
//     __KHEAP_SLAB_INDEX_BASE = -1,
// 
// #define KHEAP_SLAB_XLIST_DECL_ENUM(__NUM, __ALIGN, ...)                        \
//     KHEAP_SLAB_INDEX_##__NUM##_##__ALIGN,
//     KHEAP_SLAB_XLIST(KHEAP_SLAB_XLIST_DECL_ENUM)
// #undef KHEAP_SLAB_XLIST_DECL_ENUM
// 
//         KHEAP_NUM_SLABS
// };

struct kheap
{
    irq_lock_t lock;
    size_t heap_size;
    void *vbase;
    size_t mapped;
    struct vmem_region *region;
    size_t num_free_regions;
    ilist_t free_list;

//    struct kheap_slab
//    {
//        irq_lock_t lock;
//        struct slab_allocator *alloc;
//    } slabs[KHEAP_NUM_SLABS];
};

int
kheap_init(struct kheap *heap, void *base, size_t size);

size_t
kheap_amount_free(struct kheap *heap);

void *
kheap_alloc_specific(struct kheap *heap, order_t align_order, size_t *size);
int
kheap_free_specific(struct kheap *heap,
                    void *addr,
                    order_t align_order,
                    size_t size);

// Returns 0 if no problems are detected with the heap
int
kheap_validate(struct kheap *heap);

#endif
