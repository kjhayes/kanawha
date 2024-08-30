
#define __PAGE_ALLOCATOR__KEEP_OP_LIST
#include <kanawha/page_alloc.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/bitmap.h>
#include <kanawha/init.h>
#include <kanawha/slab.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>

// Define the page_allocator Wrapper Functions
DEFINE_OP_LIST_WRAPPERS(
        PAGE_ALLOCATOR_OP_LIST,
        static inline,
        /* No Prefix */,
        page_allocator,
        OPS_STRUCT_PTR_ACCESSOR,
        STATE_ACCESSOR)

static DECLARE_PTREE(page_allocator_interval_tree);
static DECLARE_ILIST(page_allocator_list);

#define PAGE_ALLOCATOR_SLAB_BUFFER_SIZE 0x1000
static uint8_t page_allocator_slab_buffer[PAGE_ALLOCATOR_SLAB_BUFFER_SIZE];
static struct slab_allocator *page_allocator_slab_allocator;

static int
page_alloc_static_init(void)
{
    int res;

    page_allocator_slab_allocator = create_static_slab_allocator(
            page_allocator_slab_buffer,
            PAGE_ALLOCATOR_SLAB_BUFFER_SIZE,
            sizeof(struct page_allocator),
            orderof(struct page_allocator));

    if(page_allocator_slab_allocator == NULL) {
        return -ENOMEM;
    }

    return 0;
}
declare_init_desc(static, page_alloc_static_init, "Initializing page_alloc Framework");

static struct page_allocator *
alloc_page_allocator(void)
{
    if(page_allocator_slab_allocator) 
    {
        /*
        dprintk("Allocating page_allocator struct from slab allocator: (num_slots=%lu, num_free=%lu, num_alloc=%lu)\n",
                (unsigned long)slab_objs_total(page_allocator_slab_allocator),
                (unsigned long)slab_objs_free(page_allocator_slab_allocator),
                (unsigned long)slab_objs_alloc(page_allocator_slab_allocator));
        */

        return slab_alloc(page_allocator_slab_allocator);
    } else {
        return NULL;
    }
}

void
free_page_allocator(struct page_allocator *alloc)
{
    if(page_allocator_slab_allocator) {
        slab_free(page_allocator_slab_allocator, alloc);
    }
}

int
register_page_allocator(
        struct page_allocator_ops *ops,
        void *state,
        paddr_t region_base,
        size_t region_size,
        unsigned long flags) 
{
    int res;

    struct page_allocator *allocator;
    allocator = alloc_page_allocator();
    if(allocator == NULL) {
        return -ENOMEM;
    }

    allocator->ops = ops;
    allocator->state = state;
    allocator->base = region_base;
    allocator->size = region_size;
    allocator->flags = flags;
    ilist_init(&allocator->cache_list);
    allocator->amount_cached = 0;
    allocator->num_cached = 0;

    spinlock_init(&allocator->lock);

    uintptr_t paddr_start = region_base;
    uintptr_t paddr_end = region_base + region_size;

    struct ptree_node *region_before = ptree_get_max_less(
            &page_allocator_interval_tree,
            paddr_start);

    if(region_before != NULL) {
        struct page_allocator *other = container_of(region_before, struct page_allocator, ptree_node);
        size_t other_region_end = other->base + other->size;
        if(other_region_end > region_base) {
            // We overlap the region before us
            eprintk("Cannot register page allocator which has lower overlap!\n");
            return -EEXIST;
        }
    }

    struct ptree_node *region_before_end = ptree_get_max_less(
            &page_allocator_interval_tree,
            paddr_end);

    if(region_before_end != region_before) {
        eprintk("Cannot register page allocator which has upper overlap!\n");
        return -EEXIST;
    }

    // There is no overlap, so insert the region into our interval tree,
    // and list of allocators

    res = ptree_insert(
            &page_allocator_interval_tree, 
            &allocator->ptree_node,
            paddr_start);

    if(res) {
        return res;
    }

    ilist_push_tail(&page_allocator_list, &allocator->list_node);

    return 0;
}

// These are the flags, that if set in a page_allocator,
// cannot be used unless requested explicitly
#define PAGE_ALLOC_EXPLICIT_FLAGS PAGE_ALLOC_16BIT

struct page_allocator *
page_alloc_get_allocator(
        order_t order,
        paddr_t *addr,
        unsigned long flags) 
{
    int res;
    ilist_node_t *node;
    struct page_allocator *alloc;

    DEBUG_ASSERT(order >= PAGE_ALLOC_MIN_ORDER);
    DEBUG_ASSERT(order <= PAGE_ALLOC_MAX_ORDER);

    ilist_for_each(node, &page_allocator_list) {
        alloc = container_of(node, struct page_allocator, list_node);
        if(alloc->flags == flags) {
            // This allocator is an exact match
            dprintk("page-alloc perfect match %p\n", alloc);
            res = page_allocator_alloc(alloc, order, addr);
            if(res) {
                // Failed to allocate for some reason
                dprintk("Failed to alloc (err=%s)\n", errnostr(res));
                continue;
            }

            //printk("page_alloc -> %p\n", *addr);
            return alloc;
        }
    }

    // We couldn't find a perfect match, so fall back to using any memory we can find
    // which has all of our flags set.

    ilist_for_each(node, &page_allocator_list) {
        alloc = container_of(node, struct page_allocator, list_node);
        if((alloc->flags & flags) == flags) {
            // This allocator can work, its an imperfect match though
            // We might be taking up room some rare memory type 
            // which someone else requires (ex. a 32-bit DMA region)
            
            // Make sure we have all explicit flags matched
            unsigned long required_flags = alloc->flags & PAGE_ALLOC_EXPLICIT_FLAGS;
            if((flags & required_flags) != required_flags) {
                continue;
            }

            res = page_allocator_alloc(alloc, order, addr);
            if(res) {
                // Failed to allocate for some reason
                continue;
            }

            //printk("page_alloc -> %p\n", *addr);
            return alloc;
        }
    }

    return NULL;
}
int
page_alloc(order_t order, paddr_t *addr, unsigned long flags) 
{
    struct page_allocator *alloc =
        page_alloc_get_allocator(
                order,
                addr,
                flags);
    if(alloc == NULL) {
        return -ENOMEM;
    }
    return 0;
}

int
page_free(order_t order, paddr_t addr) 
{
    //printk("page_free -> %p\n", addr);
    struct ptree_node *alloc_ptree_node = ptree_get_max_less(
                &page_allocator_interval_tree,
                addr);
    if(alloc_ptree_node == NULL) {
        return -EINVAL;
    }
    struct page_allocator *alloc = container_of(alloc_ptree_node ,struct page_allocator, ptree_node);
    return page_allocator_free(alloc, order, addr);
}

size_t
page_alloc_amount_free(void) 
{
    size_t amount = 0;
    ilist_node_t *node;
    struct page_allocator *alloc;

    ilist_for_each(node, &page_allocator_list) {
        alloc = container_of(node, struct page_allocator, list_node);
        amount += page_allocator_amount_free(alloc);
    }

    return amount;
}

size_t
page_alloc_amount_cached(void) {
    size_t amount = 0;
    ilist_node_t *node;
    struct page_allocator *alloc;

    ilist_for_each(node, &page_allocator_list) {
        alloc = container_of(node, struct page_allocator, list_node);
        amount += alloc->amount_cached;
    }

    return amount;
}

static int
dump_page_alloc_amounts(void)
{
    size_t amt_free = page_alloc_amount_free();
    size_t amt_cached = page_alloc_amount_cached();

    printk("Free Memory:   %ld MiB %ld KiB %ld Bytes\n",
            amt_free >> 20,
            (amt_free & (1ULL<<20)-1) >> 12,
            (amt_free & (1ULL<<12)-1));
    printk("Cached Memory: %ld MiB %ld KiB %ld Bytes\n",
            amt_cached >> 20,
            (amt_cached & (1ULL<<20)-1) >> 12,
            (amt_cached & (1ULL<<12)-1));

    return 0;
}
declare_init(late, dump_page_alloc_amounts);

// Cached Anonymous Pages

static int
cached_anon_page_populate(struct cached_page *page)
{
    return 0;
}
static int
cached_anon_page_flush(struct cached_page *page)
{
    return 0;
}

static int
cached_anon_page_alloc_backing(struct cached_page *page, paddr_t *out)
{
    struct cached_anon_page *anon =
        container_of(page, struct cached_anon_page, page);

    anon->cur_allocator =
        page_alloc_get_allocator(
                anon->order,
                out,
                anon->flags);

    if(anon->cur_allocator == NULL) {
        eprintk("cached_anon_page_alloc_backing(page->order=%ld, page->flags=0x%lx) failed!\n",
                anon->order, anon->flags);
        return -ENOMEM;
    }

    spin_lock(&anon->cur_allocator->lock);
    ilist_push_tail(&anon->cur_allocator->cache_list, &anon->list_node);
    anon->cur_allocator->amount_cached += (1ULL << anon->order);
    anon->cur_allocator->num_cached += 1;
    spin_unlock(&anon->cur_allocator->lock);

    return 0;
}

static int
cached_anon_page_free_backing(struct cached_page *page)
{
    int res;
    struct cached_anon_page *anon =
        container_of(page, struct cached_anon_page, page);

    spin_lock(&anon->cur_allocator->lock);
    ilist_remove(&anon->cur_allocator->cache_list, &anon->list_node);
    anon->cur_allocator->amount_cached -= (1ULL << page->order);
    anon->cur_allocator->num_cached -= 1;
    spin_unlock(&anon->cur_allocator->lock);

    res = page_free(page->order, anon->page.cur_phys_addr);
    if(res) {
        spin_lock(&anon->cur_allocator->lock);
        ilist_push_head(&anon->cur_allocator->cache_list, &anon->list_node);
        anon->cur_allocator->amount_cached += (1ULL << page->order);
        anon->cur_allocator->num_cached += 1;
        spin_unlock(&anon->cur_allocator->lock);
        return res;
    }

    anon->cur_allocator = NULL;

    return 0;
}

static struct cached_page_ops
cached_anon_page_ops = {
    .flush = cached_anon_page_flush,
    .populate = cached_anon_page_populate,
    .alloc_backing = cached_anon_page_alloc_backing,
    .free_backing = cached_anon_page_free_backing,
};

int
init_cached_anon_page(
        struct cached_anon_page *page,
        struct cached_page_ops *ops,
        order_t order,
        unsigned long flags)
{

    if(ops->alloc_backing == NULL) {
        ops->alloc_backing = cached_anon_page_alloc_backing;
    }
    if(ops->free_backing == NULL) {
        ops->free_backing = cached_anon_page_free_backing;
    }

    page->flags = flags;
    page->order = order;
    page->cur_allocator = NULL;
    init_cached_page(&page->page,
            order,
            ops);
    return 0;
}

int
deinit_cached_anon_page(
        struct cached_anon_page *page)
{
    int res;
    spin_lock(&page->page.pin_lock);

    if(page->page.pins > 0) {
        res = -EPERM;
        goto err;
    }

    if((page->page.flags & CACHED_PAGE_FLAG_PRESENT)
        && page->cur_allocator != NULL)
    {
        spin_lock(&page->cur_allocator->lock);
        ilist_remove(&page->cur_allocator->cache_list, &page->list_node);
        page->cur_allocator->amount_cached -= (1ULL << page->order);
        page->cur_allocator->num_cached -= 1;
        spin_unlock(&page->cur_allocator->lock);

        res = page_free(page->order, page->page.cur_phys_addr);
        if(res) {
            goto err;
        }
    }

    spin_unlock(&page->page.pin_lock);
    return 0;

err:
    spin_unlock(&page->page.pin_lock);
    return res;
}


struct cached_page *
page_alloc_cached(order_t order, unsigned long flags)
{
    struct cached_anon_page *page;
    page = (void*)kmalloc(sizeof(struct cached_anon_page));
    init_cached_anon_page(page, &cached_anon_page_ops, order, flags);
    return &page->page;
}

int
page_free_cached(struct cached_page *page)
{
    struct cached_anon_page *anon =
        container_of(page, struct cached_anon_page, page);

    int res;
    res = deinit_cached_anon_page(anon);
    if(res) {return res;}
    kfree(anon);
    return 0;
}

