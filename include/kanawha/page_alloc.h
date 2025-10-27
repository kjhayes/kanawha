#ifndef __KANAWHA__PAGE_ALLOC_H__
#define __KANAWHA__PAGE_ALLOC_H__

#include <kanawha/types.h>
#include <kanawha/ptree.h>
#include <kanawha/list.h>
#include <kanawha/ops.h>
#include <kanawha/lock.h>

#define PAGE_ALLOC_MIN_ORDER 9
#define PAGE_ALLOC_MAX_ORDER 21

#define PAGE_ALLOC_16BIT (1UL<<0)
#define PAGE_ALLOC_32BIT (1UL<<1)
#define PAGE_ALLOC_64BIT (0)

// Allocate some memory
// Returns 0 on success, -ENOMEM on failure
#define PAGE_ALLOCATOR_ALLOC_SIG(RET,ARG,...)\
RET(int)\
ARG(order_t, order)\
ARG(void __phys **, out)

// Must have previously called "alloc" and recevied addr the from this region
#define PAGE_ALLOCATOR_FREE_SIG(RET,ARG,...)\
RET(int)\
ARG(order_t, order)\
ARG(void __phys *, addr)

// Returns the total number of bytes which are free in this page allocator
// (This could take some time depending on the type of allocator)
#define PAGE_ALLOCATOR_AMOUNT_FREE_SIG(RET,ARG,...)\
RET(size_t)

#define PAGE_ALLOCATOR_OP_LIST(OP, ...)\
    OP(alloc, PAGE_ALLOCATOR_ALLOC_SIG, ##__VA_ARGS__)\
    OP(free, PAGE_ALLOCATOR_FREE_SIG, ##__VA_ARGS__)\
    OP(amount_free, PAGE_ALLOCATOR_AMOUNT_FREE_SIG, ##__VA_ARGS__)

struct page_allocator_ops 
{
DECLARE_OP_LIST_PTRS(PAGE_ALLOCATOR_OP_LIST, void*)
};

struct page_allocator 
{
    struct page_allocator_ops *ops;
    void *state;

    unsigned long flags;
    irq_lock_t lock;

    void __phys * base;
    size_t size;
    struct ptree_node ptree_node;

    ilist_node_t list_node;
};

int register_page_allocator(
        struct page_allocator_ops *ops,
        void *state,
        void __phys * base,
        size_t size,
        unsigned long flags);

int page_alloc(order_t order, void __phys * *addr, unsigned long flags);
int page_free(order_t order, void __phys * addr);

size_t page_alloc_amount_free(void);
size_t page_alloc_amount_matching(unsigned long flags);

// Same as page_alloc but return which allocator provided the page
// (or NULL if the allocation failed)
struct page_allocator *
page_alloc_get_allocator(
        order_t order,
        void __phys * *addr,
        unsigned long flags);

#ifndef __PAGE_ALLOCATOR__KEEP_OP_LIST
#undef PAGE_ALLOCATOR_ALLOC_SIG
#undef PAGE_ALLOCATOR_FREE_SIG
#undef PAGE_ALLOCATOR_AMOUNT_FREE_SIG
#undef PAGE_ALLOCATOR_OP_LIST
#endif

#endif
