#ifndef __KANAWHA__KHEAP_H__
#define __KANAWHA__KHEAP_H__

#include <kanawha/string.h>
#include <kanawha/buddy.h>
#include <kanawha/mem_flags.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/export.h>

struct kheap {
    size_t heap_size;
    void * vbase;
    size_t mapped;
    struct vmem_region *region;

    size_t num_free_regions;
    ilist_t free_list;
};

int
kheap_init(
        struct kheap *heap,
        void * base,
        size_t size);

size_t kheap_amount_free(struct kheap *heap);

void *
kheap_alloc_specific(
        struct kheap *heap,
        order_t align_order,
        size_t *size);
int
kheap_free_specific(
        struct kheap *heap,
        void *addr,
        size_t size);

// Returns 0 if no problems are detected with the heap
int
kheap_validate(struct kheap *heap);

#endif
