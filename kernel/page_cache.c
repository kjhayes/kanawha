
#include <kanawha/page_cache.h>
#include <kanawha/stddef.h>

int
init_cached_page(
        struct cached_page *pg,
        order_t order,
        struct cached_page_ops *ops)
{
    pg->order = order;
    pg->ops = ops;
    pg->flags = 0;

    // Starts out with zero references
    pg->pins = 0;
    spinlock_init(&pg->pin_lock);

    ilist_init(&pg->callback_list);

    return 0;
}

// Assumes we have the lock held
static int
__cached_page_get(struct cached_page *page)
{
    int res;
    if(!(page->flags & CACHED_PAGE_FLAG_PRESENT)) {
        paddr_t addr;
        res = direct_cached_page_alloc_backing(page, &addr);
        if(res) {
            eprintk("direct_cached_page_alloc_backing returned (%s)\n",
                    errnostr(res));
            return res;
        }
        page->flags |= CACHED_PAGE_FLAG_PRESENT;
        page->cur_phys_addr = addr;

        res = direct_cached_page_populate(page);
        if(res) {
            eprintk("direct_cached_page_populate returned (%s)\n",
                    errnostr(res));
            direct_cached_page_free_backing(page);
            return res;
        }

        page->flags |= CACHED_PAGE_FLAG_POPULATED;

        int res = 0;
        ilist_node_t *callback_node;
        ilist_for_each(callback_node, &page->callback_list) {
            struct cached_page_callbacks *callbacks =
                container_of(callback_node, struct cached_page_callbacks, list_node);

            if(callbacks->ops->instantiated) {
                int callback_res = (*callbacks->ops->instantiated)(page, callbacks->priv_state);
                if(callback_res) {
                    eprintk("__cached_page_get: instantiated callback %p failed with error (%s)\n",
                            callbacks->ops->instantiated, errnostr(callback_res));
                    res = callback_res;
                    if(res) {
                        eprintk("cached_page callback returned (%s)\n",
                                errnostr(res));
                    }
                }
            }
        }

        return res;
    }

    return 0;
}

int
cached_page_get(struct cached_page *page)
{
    int res;
    spin_lock(&page->pin_lock);

    res = __cached_page_get(page);
    if(res) {
        eprintk("__cached_page_get returned: (%s)\n",
                errnostr(res));
        goto err;
    }

    page->pins++;
    page->flags |= CACHED_PAGE_FLAG_DIRTY;

    spin_unlock(&page->pin_lock);
    return 0;

err:
    spin_unlock(&page->pin_lock);
    return res;
}

int
cached_page_get_readonly(struct cached_page *page)
{
    int res;
    spin_lock(&page->pin_lock);

    res = __cached_page_get(page);
    if(res) {
        goto err;
    }

    page->pins++;

    spin_unlock(&page->pin_lock);
    return 0;

err:
    spin_unlock(&page->pin_lock);
    return res;
}

int
cached_page_touch(struct cached_page *page)
{
    int res;
    spin_lock(&page->pin_lock);

    res = __cached_page_get(page);
    if(res) {
        goto err;
    }

    page->flags |= CACHED_PAGE_FLAG_DIRTY;

    spin_unlock(&page->pin_lock);
    return 0;

err:
    spin_unlock(&page->pin_lock);
    return res;

}

int
cached_page_touch_readonly(struct cached_page *page)
{
    int res;
    spin_lock(&page->pin_lock);

    res = __cached_page_get(page);
    if(res) {
        goto err;
    }

    spin_unlock(&page->pin_lock);
    return 0;

err:
    spin_unlock(&page->pin_lock);
    return res;

}

int
cached_page_put(struct cached_page *page)
{
    spin_lock(&page->pin_lock);
    page->pins--;
    spin_unlock(&page->pin_lock);
    return 0;
}

int
cached_page_add_callbacks(
        struct cached_page *page,
        struct cached_page_callbacks *callbacks)
{
    spin_lock(&page->pin_lock);
    ilist_push_tail(&page->callback_list, &callbacks->list_node);
    spin_unlock(&page->pin_lock);
    return 0;
}

int
cached_page_remove_callbacks(
        struct cached_page *page,
        struct cached_page_callbacks *callbacks)
{
    spin_lock(&page->pin_lock);
    ilist_remove(&page->callback_list, &callbacks->list_node);
    spin_unlock(&page->pin_lock);
    return 0;
}

int
reclaim_cached_page(struct cached_page *page)
{
    int res = 0;
    spin_lock(&page->pin_lock);

    if(page->pins > 0) {
        // We cannot reclaim a page which is pinned
        spin_unlock(&page->pin_lock);
        return -EBUSY;
    }

    if(page->flags & CACHED_PAGE_FLAG_PRESENT) {

        int res = 0;
        ilist_node_t *callback_node;
        ilist_for_each(callback_node, &page->callback_list) {
            struct cached_page_callbacks *callbacks =
                container_of(callback_node, struct cached_page_callbacks, list_node);
            if(callbacks->ops->reclaim) {
                int callback_res = (*callbacks->ops->reclaim)(page, callbacks->priv_state);
                if(callback_res) {
                    eprintk("reclaim_cached_page: reclaim callback %p failed with error (%s)\n",
                            callbacks->ops->reclaim, errnostr(callback_res));
                    res = callback_res;
                }
            }
        }
        if(res) {
            spin_unlock(&page->pin_lock);
            return res;
        }

        if(page->flags & CACHED_PAGE_FLAG_DIRTY) {
            direct_cached_page_flush(page);
        }
        direct_cached_page_free_backing(page);
    }

    spin_unlock(&page->pin_lock);
    return res;
}

// Sub-Pages

static int
subpage_flush(struct cached_page *page) {
    struct cached_subpage *subpage =
        container_of(page, struct cached_subpage, page);
    return direct_cached_page_flush(subpage->parent);
}

static int
subpage_populate(struct cached_page *page) {
    // Do nothing
    return 0;
}

static int
subpage_alloc_backing(struct cached_page *page, paddr_t *out) {
    struct cached_subpage *subpage =
        container_of(page, struct cached_subpage, page);
    int res = cached_page_get(subpage->parent);
    if(res) {return res;}
    *out = subpage->parent->cur_phys_addr + subpage->offset;
    return 0;
}

static int
subpage_free_backing(struct cached_page *page) {
    struct cached_subpage *subpage =
        container_of(page, struct cached_subpage, page);
    return cached_page_put(subpage->parent);
}

static struct cached_page_ops
subpage_ops = {
    .flush = subpage_flush,
    .populate = subpage_populate,
    .alloc_backing = subpage_alloc_backing,
    .free_backing = subpage_free_backing,
};

int
init_cached_subpage(
        struct cached_subpage *subpage,
        order_t subpage_order,
        size_t subpage_offset,
        struct cached_page *parent)
{
    subpage->parent = parent;
    subpage->offset = subpage_offset;
    return init_cached_page(
            &subpage->page,
            subpage_order,
            &subpage_ops);
}

// Direct Pages

static int
ram_page_flush(struct cached_page *page)
{
    // Do Nothing (Maybe we should flush caches?)
    return 0;
}

static int
ram_page_populate(struct cached_page *page)
{
    // Do Nothing
    return 0;
}

static int
ram_page_alloc_backing(struct cached_page *page, paddr_t *out) {
    struct cached_ram_page *ram =
        container_of(page, struct cached_ram_page, page);
    *out = ram->addr;
    return 0;
}

static int
ram_page_free_backing(struct cached_page *page)
{
    // Do Nothing
    return 0;
}

static struct cached_page_ops
ram_page_ops = {
    .flush = ram_page_flush,
    .populate = ram_page_populate,
    .alloc_backing = ram_page_alloc_backing,
    .free_backing = ram_page_free_backing,
};

int
init_cached_ram_page(
        struct cached_ram_page *page,
        order_t order,
        paddr_t addr)
{
    page->addr = addr;
    return init_cached_page(
            &page->page,
            order,
            &ram_page_ops);
}

