#ifndef __KANAWHA__FS_PAGE_H__
#define __KANAWHA__FS_PAGE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/pcache.h>
#include <kanawha/page.h>

struct fs_node;

#define FS_PAGE_FLAG_DIRTY (1UL << 0)
struct fs_page
{
    struct page page;
    unsigned long flags;
    struct fs_node *fs_node;
    struct pcache_node cache_node;
};

struct fs_page *
fs_page_raw_alloc(
        void __phys *paddr,
        order_t order,
        struct fs_node *node,
        unsigned long flags);

int
fs_page_raw_free(
        struct fs_page *);

static inline void __phys *
fs_page_phys(
        struct fs_page *page)
{
    return page_get_phys(&page->page);
}
static inline order_t
fs_page_order(
        struct fs_page *page)
{
    return page_get_order(&page->page);
}
static inline size_t
fs_page_size(
        struct fs_page *page)
{
    return page_get_size(&page->page);
}

#endif
