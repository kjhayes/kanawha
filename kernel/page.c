
#include <kanawha/page.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/atomic.h>

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

// Anonymous Pages

struct anon_page {
    struct page page;
    atomic_t refcount;
};

static int
anon_page_page_get(
        struct page *page)
{
    struct anon_page *anon =
        container_of(page, struct anon_page, page);

    atomic_val_t old = atomic_fetch_inc(&anon->refcount);
    DEBUG_ASSERT(old > 0);

    return 0;
}
static int
anon_page_page_put(
        struct page *page)
{
    struct anon_page *anon =
        container_of(page, struct anon_page, page);

    atomic_val_t old = atomic_fetch_dec(&anon->refcount);
    if(old == 1) {
        // Free the backing memory
        page_free(page_get_order(page), page_get_phys(page));
        kfree(anon);
    }

    return 0;
}
static int
anon_page_page_mark(
        struct page *page,
        unsigned long status)
{
    // Nothing to do
    return 0;
}

static struct page_ops anon_page_ops = {
    .flush = page_nop_flush,
    .get = anon_page_page_get,
    .put = anon_page_page_put,
    .mark = anon_page_page_mark,
};

struct page *
page_get_anonymous(
        order_t order)
{
    int res;

    struct anon_page *anon;
    anon = kzmalloc(sizeof(*anon), KM_KERNEL);
    if(anon == NULL) {
        return NULL;
    }

    atomic_set_relaxed(&anon->refcount, 1);

    void __phys *paddr;
    res = page_alloc(order, &paddr, PAGE_ALLOC_64BIT);
    if(res) {
        kfree(anon);
        return NULL;
    }

    res = page_init(
            &anon->page,
            paddr,
            order,
            &anon_page_ops);
    if(res) {
        kfree(anon);
        return NULL;
    }

    return &anon->page;
}

