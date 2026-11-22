#ifndef __KANAWHA__FS_PAGE_H__
#define __KANAWHA__FS_PAGE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/pcache.h>
#include <kanawha/mpage.h>

struct fs_node;

#define FS_PAGE_FLAG_DIRTY (1UL << 0)
struct fs_page
{
    struct mpage mpage;
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

int
fs_page_get(struct fs_page *page);
int
fs_page_put(struct fs_page *page);
int
fs_page_mark_dirty(
        struct fs_page *page);
int
fs_page_mark_clean(
        struct fs_page *page);
int
fs_page_is_dirty(
        struct fs_page *page);

static inline struct mpage *
fs_page_get_as_mpage(
        struct fs_page *fs_page)
{
    struct mpage *page = &fs_page->mpage;
    mpage_get(page);
    return page;
}

static inline void __phys *
fs_page_phys(
        struct fs_page *page)
{
    return mpage_get_phys(&page->mpage);
}
static inline order_t
fs_page_order(
        struct fs_page *page)
{
    return mpage_get_order(&page->mpage);
}
static inline size_t
fs_page_size(
        struct fs_page *page)
{
    return mpage_get_size(&page->mpage);
}

#endif
