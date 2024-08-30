#ifndef __KANAWHA__PAGE_ALLOC_H__
#define __KANAWHA__PAGE_ALLOC_H__

#include <kanawha/stdint.h>
#include <kanawha/ptree.h>
#include <kanawha/list.h>
#include <kanawha/ops.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_cache.h>

#define PAGE_ALLOC_MIN_ORDER 12
#define PAGE_ALLOC_MAX_ORDER 21

#define PAGE_ALLOC_16BIT (1UL<<0)
#define PAGE_ALLOC_32BIT (1UL<<1)

// Allocate some memory
// Returns 0 on success, -ENOMEM on failure
#define PAGE_ALLOCATOR_ALLOC_SIG(RET,ARG)\
RET(int)\
ARG(order_t, order)\
ARG(paddr_t*, out)

// Must have previously called "alloc" and recevied addr the from this region
#define PAGE_ALLOCATOR_FREE_SIG(RET,ARG)\
RET(int)\
ARG(order_t, order)\
ARG(paddr_t, addr)

// Returns the total number of bytes which are free in this page allocator
// (This could take some time depending on the type of allocator)
#define PAGE_ALLOCATOR_AMOUNT_FREE_SIG(RET,ARG)\
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
    spinlock_t lock;

    paddr_t base;
    size_t size;
    struct ptree_node ptree_node;

    ilist_node_t list_node;

    // List of reclaimable pages
    size_t amount_cached;
    size_t num_cached;
    ilist_t cache_list;
};

int register_page_allocator(
        struct page_allocator_ops *ops,
        void *state,
        paddr_t base,
        size_t size,
        unsigned long flags);

int page_alloc(order_t order, paddr_t *addr, unsigned long flags);
int page_free(order_t order, paddr_t addr);
size_t page_alloc_amount_free(void);
size_t page_alloc_amount_cached(void);
size_t page_alloc_amount_matching(unsigned long flags);

// Same as page_alloc but return which allocator provided the page
// (or NULL if the allocation failed)
struct page_allocator *
page_alloc_get_allocator(
        order_t order,
        paddr_t *addr,
        unsigned long flags);

#ifndef __PAGE_ALLOCATOR__KEEP_OP_LIST
#undef PAGE_ALLOCATOR_ALLOC_SIG
#undef PAGE_ALLOCATOR_FREE_SIG
#undef PAGE_ALLOCATOR_AMOUNT_FREE_SIG
#undef PAGE_ALLOCATOR_OP_LIST
#endif

struct cached_anon_page {
    struct cached_page page;
    struct page_allocator *cur_allocator;
    order_t order;
    unsigned long flags;
    ilist_node_t list_node;
};

// In-Place Initialization of an anonymous page
int
init_cached_anon_page(
        struct cached_anon_page *page,
        struct cached_page_ops *ops, // Can provide non-NULL values for functions
                                     // other than alloc and free
        order_t order,
        unsigned long flags);

int
deinit_cached_anon_page(
        struct cached_anon_page *page);

// Malloc'ed initialization of an anonymous page
struct cached_page *
page_alloc_cached(
        order_t order,
        unsigned long flags);
int
page_free_cached(
        struct cached_page *page);

#endif
