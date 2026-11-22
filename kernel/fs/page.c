
#include <kanawha/fs/page.h>
#include <kanawha/kmalloc.h>

struct fs_page *
fs_page_raw_alloc(
        void __phys *paddr,
        order_t order,
        unsigned long flags)
{
    struct fs_page *page;
    page = kzmalloc(sizeof(struct fs_page), KM_KERNEL);
    if(page == NULL)
    {
        return NULL;
    }
    page->paddr = paddr;
    page->order = order;
    page->flags = flags;
    return page;
}

int
fs_page_raw_free(
        struct fs_page *page)
{
    kfree(page);
    return 0;
}

