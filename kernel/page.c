
#include <kanawha/page.h>
#include <kanawha/kmalloc.h>

int
page_init(
        struct page *page,
        void __phys *paddr,
        order_t order,
        struct page_ops *ops)
{
    page->paddr = paddr;
    page->order = order;
    page->ops = ops;
    return 0;
}

int
page_deinit(
        struct page *page)
{
    return 0;
}

void __phys *
page_get_phys(
        struct page *page)
{
    return page->paddr;
}
order_t
page_get_order(
        struct page *page)
{
    return page->order;
}
size_t
page_get_size(
        struct page *page)
{
    return 1UL<<page_get_order(page);
}

// Default Implementations
int
page_nop_flush(
        struct page *page)
{
    return 0;
}

