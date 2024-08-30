#ifndef __KANAWHA__PAGE_CACHE_H__
#define __KANAWHA__PAGE_CACHE_H__

#include <kanawha/stdint.h>
#include <kanawha/ops.h>
#include <kanawha/spinlock.h>
#include <kanawha/list.h>

struct cached_page;

#define CACHED_PAGE_FLAG_PRESENT   (1ULL<<0)
#define CACHED_PAGE_FLAG_POPULATED (1ULL<<1)
#define CACHED_PAGE_FLAG_DIRTY     (1ULL<<2)

// Fill out the page with the correct fields,
// cached_page->cur_phys_addr will be a valid
// physical address of size (1ULL<<cached_page->order)
#define CACHED_PAGE_POPULATE_SIG(RET,ARG)\
RET(int)

#define CACHED_PAGE_FLUSH_SIG(RET,ARG)\
RET(int)

// Allocate the backing memory for a page
#define CACHED_PAGE_ALLOC_BACKING_SIG(RET,ARG)\
RET(int)\
ARG(paddr_t *, out_phys_addr)

// Free the backing memory for a page
#define CACHED_PAGE_FREE_BACKING_SIG(RET,ARG)\
RET(int)

#define CACHED_PAGE_OP_LIST(OP, ...)\
    OP(populate, CACHED_PAGE_POPULATE_SIG, ##__VA_ARGS__)\
    OP(flush, CACHED_PAGE_FLUSH_SIG, ##__VA_ARGS__)\
    OP(alloc_backing, CACHED_PAGE_ALLOC_BACKING_SIG, ##__VA_ARGS__)\
    OP(free_backing, CACHED_PAGE_FREE_BACKING_SIG, ##__VA_ARGS__)

struct cached_page_ops {
DECLARE_OP_LIST_PTRS(CACHED_PAGE_OP_LIST,struct cached_page*)
};

struct cached_page
{
    struct cached_page_ops *ops;
    order_t order;

    unsigned long flags;

    spinlock_t pin_lock;
    int pins;

    ilist_t callback_list;

    // These fields are only valid after a call to "get_cached_page"
    // and should be considered invalid after a call to "put_cached_page"
    paddr_t cur_phys_addr;
};

// Initialize a "cached" page, which can be "reclaimed"
// Access to the page's contents will need to be between "get" and "put" calls
// to ensure it isn't concurrently reclaimed
//
// The page may be populated lazily, so it's possible no reclaim_ops functions
// will be called by page_alloc_cached.
int
init_cached_page(
        struct cached_page *page,
        order_t order,
        struct cached_page_ops *reclaim_ops);

// Free a cached page
//
// NOTE: This does not "reclaim" the page, it just frees the structure and any
// backing physical memory. So if this page is supposed to represent a disk block,
// nothing will be written back to disk by page_free_cached, that must be done by
// a higher level API.
int
cached_page_destroy(struct cached_page *page);

// Pin the cached page in place
// Returns 0 on success, negative errno on failure
// (May fail if this page is in the process of being freed)
int
cached_page_get(struct cached_page *page);

// Pin the cached page in place and promise we will only read from it
// Returns 0 on success, negative errno on failure
int
cached_page_get_readonly(struct cached_page *page);

// Bring the cached page into memory,
// but do not pin it, functions equivalently to
// a "get_*" immediately followed by a "put" but
// can be better optimized
int
cached_page_touch(struct cached_page *page);
int
cached_page_touch_readonly(struct cached_page *page);

// Un-Pin the cached page
// Returns zero on success
int
cached_page_put(struct cached_page *page);

static inline paddr_t
cached_page_addr(struct cached_page *page)
{
    return page->cur_phys_addr;
}

// Reclaim a Cached Page
int
reclaim_cached_page(struct cached_page *page);

DEFINE_OP_LIST_WRAPPERS(
        CACHED_PAGE_OP_LIST,
        static inline,
        direct_,
        cached_page,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

#undef CACHED_PAGE_OP_LIST
#undef CACHED_PAGE_FLUSH_SIG
#undef CACHED_PAGE_POPULATE_SIG
#undef CACHED_PAGE_ALLOC_BACKING_SIG
#undef CACHED_PAGE_FREE_BACKING_SIG

struct cached_page_callback_ops
{
    int(*reclaim)(struct cached_page *page, void *priv_state);
    int(*instantiated)(struct cached_page *page, void *priv_state);
};

struct cached_page_callbacks
{
    struct cached_page_callback_ops *ops;
    void *priv_state;
    ilist_node_t list_node;
};

/*
 * Add this callback structure to the list of callbacks for the cached_page.
 */
int
cached_page_add_callbacks(
        struct cached_page *page,
        struct cached_page_callbacks *callbacks);

int
cached_page_remove_callbacks(
        struct cached_page *page,
        struct cached_page_callbacks *callbacks);

/*
 * Sub-Pages
 */

struct cached_subpage {
    struct cached_page page;
    size_t offset;
    struct cached_page *parent;
};

// We can implement a generic "subpage" cached page, which will attach to a large cached page
// and allow access at finer granularities without allocating more backing memory
// 
// Flushing a subpage just flushes the parent page
// alloc/free just do a "get/put" on the parent and compute the physical offset
int
init_cached_subpage(
        struct cached_subpage *subpage,
        order_t subpage_order,
        size_t subpage_offset,
        struct cached_page *parent_page);

/*
 * "RAM" Pages
 */

// RAM pages aren't cached at all, they just pretend to be
// cached but directly access some physical memory.
// This is just useful for interfaces which normally accept
// "struct cached_page" but that have a constant physical address.
// (Ex. ramdisks)

struct cached_ram_page {
    struct cached_page page;
    paddr_t addr;
};

int
init_cached_ram_page(
    struct cached_ram_page *ram_page,
    order_t order,
    paddr_t addr);

#endif
