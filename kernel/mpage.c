
#include <kanawha/mpage.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/atomic.h>

int
mpage_init(
        struct mpage *mpage,
        void __phys *paddr,
        order_t order,
        struct mpage_ops *ops)
{
    mpage->paddr = paddr;
    mpage->order = order;
    mpage->ops = ops;
    return 0;
}

int
mpage_deinit(
        struct mpage *mpage)
{
    return 0;
}

void __phys *
mpage_get_phys(
        struct mpage *mpage)
{
    return mpage->paddr;
}
order_t
mpage_get_order(
        struct mpage *mpage)
{
    return mpage->order;
}
size_t
mpage_get_size(
        struct mpage *mpage)
{
    return 1UL<<mpage_get_order(mpage);
}

// Default Implementations
int
mpage_nop_flush(
        struct mpage *mpage)
{
    return 0;
}

// Anonymous Pages

struct anon_mpage {
    struct mpage mpage;
    atomic_t refcount;
};

static int
anon_mpage_get(
        struct mpage *mpage)
{
    struct anon_mpage *anon =
        container_of(mpage, struct anon_mpage, mpage);

    atomic_val_t old = atomic_fetch_inc(&anon->refcount);
    DEBUG_ASSERT(old > 0);

    return 0;
}
static int
anon_mpage_put(
        struct mpage *mpage)
{
    struct anon_mpage *anon =
        container_of(mpage, struct anon_mpage, mpage);

    atomic_val_t old = atomic_fetch_dec(&anon->refcount);
    if(old == 1) {
        // Free the backing memory
        page_free(mpage_get_order(mpage), mpage_get_phys(mpage));
        kfree(anon);
    }

    return 0;
}
static int
anon_mpage_mark(
        struct mpage *mpage,
        unsigned long status)
{
    // Nothing to do
    return 0;
}

static struct mpage_ops anon_mpage_ops = {
    .flush = mpage_nop_flush,
    .get = anon_mpage_get,
    .put = anon_mpage_put,
    .mark = anon_mpage_mark,
};

struct mpage *
mpage_get_anonymous(
        order_t order)
{
    int res;

    struct anon_mpage *anon;
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

    res = mpage_init(
            &anon->mpage,
            paddr,
            order,
            &anon_mpage_ops);
    if(res) {
        kfree(anon);
        return NULL;
    }

    return &anon->mpage;
}

