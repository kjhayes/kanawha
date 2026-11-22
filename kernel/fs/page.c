
#include <kanawha/fs/page.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>

struct fs_node;

static struct mpage_ops fs_page_mpage_ops;

struct fs_page *
fs_page_raw_alloc(
        void __phys *paddr,
        order_t order,
        struct fs_node *fs_node,
        unsigned long flags)
{
    int res;
    struct fs_page *page;
    page = kzmalloc(sizeof(struct fs_page), KM_KERNEL);
    if(page == NULL)
    {
        return NULL;
    }
    page->flags = flags;
    page->fs_node = fs_node;
    res = mpage_init(
            &page->mpage,
            paddr,
            order,
            &fs_page_mpage_ops);
    if(res) {
        kfree(page);
        return NULL;
    }
    return page;
}

int
fs_page_raw_free(
        struct fs_page *page)
{
    mpage_deinit(&page->mpage);
    kfree(page);
    return 0;
}

int
fs_page_get(struct fs_page *page)
{
    pcache_node_get(&page->cache_node);
    return 0;
}

int
fs_page_put(struct fs_page *page)
{
    pcache_node_put(&page->cache_node);
    return 0;
}

int
fs_page_mark_dirty(
        struct fs_page *page)
{
    page->flags |= FS_PAGE_FLAG_DIRTY;
    return 0;
}
int
fs_page_mark_clean(
        struct fs_page *page)
{
    page->flags &= ~FS_PAGE_FLAG_DIRTY;
    return 0;
}
int
fs_page_is_dirty(
        struct fs_page *page)
{
    return page->flags & FS_PAGE_FLAG_DIRTY;
}

// page_ops
static inline int
fs_page_mpage_flush(
        struct mpage *page)
{
    struct fs_page *fs_page =
        container_of(page, struct fs_page, mpage);
    return fs_node_flush_fs_page(fs_page->fs_node, fs_page);
}

static inline int
fs_page_mpage_get(
        struct mpage *page)
{
    struct fs_page *fs_page =
        container_of(page, struct fs_page, mpage);
    return fs_page_get(fs_page);
}

static inline int
fs_page_mpage_put(
        struct mpage *page)
{
    struct fs_page *fs_page =
        container_of(page, struct fs_page, mpage);
    return fs_page_put(fs_page);
}

static inline int
fs_page_mpage_mark(
        struct mpage *page,
        unsigned long status)
{
    struct fs_page *fs_page =
        container_of(page, struct fs_page, mpage);
    if(status & MPAGE_MARK_DIRTY) {
        fs_page_mark_dirty(fs_page);
    }
    return 0;
}

static struct mpage_ops fs_page_mpage_ops = {
    .flush = fs_page_mpage_flush,
    .get = fs_page_mpage_get,
    .put = fs_page_mpage_put,
    .mark = fs_page_mpage_mark,
};

