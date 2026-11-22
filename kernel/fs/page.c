
#include <kanawha/fs/page.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>

struct fs_node;

static struct page_ops fs_page_page_ops;

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
    res = page_init(
            &page->page,
            paddr,
            order,
            &fs_page_page_ops);
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
    page_deinit(&page->page);
    kfree(page);
    return 0;
}

static inline int
fs_page_page_flush(
        struct page *page)
{
    struct fs_page *fs_page =
        container_of(page, struct fs_page, page);
    return fs_node_flush_fs_page(fs_page->fs_node, fs_page);
}

static struct page_ops fs_page_page_ops = {
    .flush = fs_page_page_flush,
};

