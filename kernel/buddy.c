
#ifdef CONFIG_DEBUG_BUDDY_ALLOC
#define DEBUG
#endif
#include <kanawha/printk.h>

#include <kanawha/bitmap.h>
#include <kanawha/buddy.h>
#include <kanawha/errno.h>
#include <kanawha/list.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/slab.h>
#include <kanawha/init.h>

struct buddy_page
{
    struct buddy_page __phys *next;
    struct buddy_page __phys *prev;

    // Is this free page the base of the region (making "order" valid)?
    order_t order;
};

struct buddy_order
{
    order_t order;
    size_t num_pages;

    struct buddy_page __phys *page_list;
};

struct buddy_region
{
    void __phys *region_base;
    size_t region_size;

    order_t min_order;
    order_t max_order;

    size_t order_lists_offset;
    size_t order_lists_bytes;

    size_t bitmap_offset;
    size_t bitmap_bytes;

    size_t pages_offset;
    size_t pages_bytes;
};

static inline void
buddy_bitmap_set(
        struct buddy_region *region,
        size_t bit)
{
    unsigned long __phys *bitmap_phys = region->region_base + region->bitmap_offset;
    unsigned long *bitmap = __va(bitmap_phys);
    bitmap_set(bitmap, bit);
}
static inline void
buddy_bitmap_clear(
        struct buddy_region *region,
        size_t bit)
{
    unsigned long __phys *bitmap_phys = region->region_base + region->bitmap_offset;
    unsigned long *bitmap = __va(bitmap_phys);
    bitmap_clear(bitmap, bit);
}
static inline int
buddy_bitmap_check(
        struct buddy_region *region,
        size_t bit)
{
    unsigned long __phys *bitmap_phys = region->region_base + region->bitmap_offset;
    unsigned long *bitmap = __va(bitmap_phys);
    return bitmap_check(bitmap, bit);
}

static inline size_t
buddy_region_num_orders(struct buddy_region *region)
{
    return (region->max_order - region->min_order) + 1;
}

static inline size_t
buddy_order_total_free(struct buddy_order *order)
{
    return (1ULL << order->order) * order->num_pages;
}

// #ifdef CONFIG_DEBUG_BUDDY_ALLOC
// static inline void
// buddy_region_dump_orders(struct buddy_region *region, printk_f *printer)
// {
//     size_t num_orders = buddy_region_num_orders(region);
//     for(size_t i = 0; i < num_orders; i++)
//     {
//         struct buddy_order *order = &region->order_lists[i];
//         size_t total_free = buddy_order_total_free(order);
// 
//         (*printer)("order[%d] -> num_pages=0x%lx, page_size=0x%lx, "
//                    "total_free=0x%lx\n",
//                    order->order,
//                    (unsigned long)order->num_pages,
//                    (1UL << (order->order)),
//                    (unsigned long)total_free);
//     }
// }
// #endif

size_t
buddy_region_total_free(struct buddy_region *region)
{
    size_t size = 0;
    struct buddy_order __phys *orders_phys = region->region_base + region->order_lists_offset;
    for(order_t i = 0; i < buddy_region_num_orders(region); i++)
    {
        struct buddy_order *buddy_order = __va(&orders_phys[i]);
        size += buddy_order_total_free(buddy_order);
    }
    return size;
}

static size_t
buddy_region_total_owned(struct buddy_region *region)
{
    return region->region_size;
}

static inline int
buddy_order_push_page(
        struct buddy_region *region,
        order_t order,
        struct buddy_page __phys *page_phys)
{
    size_t index = order - region->min_order;
    struct buddy_order __phys *order_phys = region->region_base + region->order_lists_offset + (sizeof(struct buddy_order) * index);
    struct buddy_order *buddy_order = __va(order_phys);

    struct buddy_page *page = __va(page_phys);

    page->order = order;

    // Push the page onto the front of the list
    page->prev = NULL;
    page->next = buddy_order->page_list;
    buddy_order->page_list = page_phys;

    buddy_order->num_pages++;
    return 0;
}

static inline int
buddy_order_pop_page(
        struct buddy_region *region,
        order_t order,
        struct buddy_page __phys **page_out)
{
    size_t index = order - region->min_order;
    struct buddy_order __phys *order_phys = region->region_base + region->order_lists_offset + (sizeof(struct buddy_order) * index);
    struct buddy_order *buddy_order = __va(order_phys);

    if(buddy_order->num_pages <= 0)
    {
        return -ENOMEM;
    }

    // Pop from the front of the list
    struct buddy_page __phys *page_phys = buddy_order->page_list;
    struct buddy_page *page = __va(page_phys);
    buddy_order->page_list = page->next;
    if(buddy_order->num_pages > 1) {
        struct buddy_page *new_front_page = __va(buddy_order->page_list);
        new_front_page->prev = NULL;
    }

    *page_out = page_phys;

    buddy_order->num_pages--;
    return 0;
}

static inline int
buddy_order_remove_page(
        struct buddy_region *region,
        order_t order,
        struct buddy_page __phys *page_phys)
{
    size_t index = order - region->min_order;
    struct buddy_order __phys *order_phys = region->region_base + region->order_lists_offset + (sizeof(struct buddy_order) * index);
    struct buddy_order *buddy_order = __va(order_phys);

    if(buddy_order->num_pages <= 0)
    {
        return -ENOMEM;
    }

    struct buddy_page *page = __va(page_phys);

    struct buddy_page __phys *iter_phys = buddy_order->page_list;
    for(size_t i = 0; i < buddy_order->num_pages; i++) {
        struct buddy_page *iter = __va(iter_phys);
        if(iter_phys == page_phys) {
            if(i == 0) {
                // This is the first entry
                buddy_order->page_list = page->next;
                if(buddy_order->num_pages > 1) {
                    struct buddy_page *new_front_page = __va(buddy_order->page_list);
                    new_front_page->prev = NULL;
                }
            } else {
                // "page->prev" is valid
                struct buddy_page *prev = __va(page->prev);
                page->prev->next = page->next;
                if(i < buddy_order->num_pages-1) {
                    // "page->next" is valid
                    struct buddy_page *next = __va(page->next);
                    next->prev = page->prev;
                }
            }
            page->next = NULL;
            page->prev = NULL;
            break;
        } else {
            iter_phys = iter->next;
        }
    }
    
    buddy_order->num_pages--;
    return 0;
}

int
buddy_region_free(
        struct buddy_region *region,
        order_t order,
        void __phys *page_phys)
{
    dprintk("Freeing page: %p of order %d\n", page_addr, order);
    struct buddy_page *page = __va(page_phys);
    page->order = order;
    page->next = NULL;
    page->prev = NULL;

    uintptr_t region_offset;
    uintptr_t pages_offset;
    DEBUG_ASSERT(page_phys >= region->region_base);
    region_offset = (uintptr_t)page_phys - (uintptr_t)region->region_base;
    DEBUG_ASSERT(region_offset < region->region_size);
    DEBUG_ASSERT(region_offset >= region->pages_offset);
    pages_offset = region_offset - region->pages_offset;
    DEBUG_ASSERT_MSG(pages_offset < region->pages_bytes,
            "buddy_region_free: page=%p, pages_offset=0x%lx, pages_base_offset=0x%lx, pages_bytes=0x%lx",
            page_phys,
            (ul_t)pages_offset,
            (ul_t)region->pages_offset,
            (ul_t)region->pages_bytes
            );

    // Note: We aren't necessarily a min_order page but we still care about
    // this index to access the bitmap
    size_t min_page_index = pages_offset >> region->min_order;

    // Try to find a buddy page to go with this one

    if(order + 1 > region->max_order) {
        goto no_buddy;
    }

    struct buddy_page __phys *buddy_phys =
        (struct buddy_page __phys *)((uintptr_t)page_phys ^ (1ULL << order));

    uintptr_t buddy_region_offset;
    uintptr_t buddy_pages_offset;

    if((void __phys *)buddy_phys < region->region_base) {
        goto no_buddy;
    }
    buddy_region_offset = (uintptr_t)buddy_phys - (uintptr_t)region->region_base;
    if(buddy_region_offset >= region->region_size) {
        goto no_buddy;
    }
    buddy_pages_offset = buddy_region_offset - region->pages_offset;
    if(buddy_pages_offset >= region->pages_bytes) {
        goto no_buddy;
    }

    size_t buddy_min_page_index = buddy_pages_offset >> region->min_order;

    dprintk("min_page_index=0x%llx, buddy_min_page_index=0x%llx\n",
            (unsigned long long)min_page_index,
            (unsigned long long)buddy_min_page_index);

    if(!buddy_bitmap_check(region, buddy_min_page_index)) {
        dprintk("buddy is not free (index=%lu, buddy-index=%lu)!\n",
                (ul_t)min_page_index,
                (ul_t)buddy_min_page_index);

        goto no_buddy;
    }

    struct buddy_page *buddy_page = __va(buddy_phys);
    if(buddy_page->order != order)
    {
        dprintk("buddy has wrong order (order=%d, buddy-order=%d)!\n",
                (int)order,
                (int)buddy_page->order);
        goto no_buddy;
    }

    // Our buddy exists and is valid!
    dprintk("coalescing buddy!\n");
   
    // Remove our buddy from the order's free list
    buddy_order_remove_page(region, order, buddy_phys);

    // Figure out which page is the start of the coalesced page (lower)
    size_t lower_min_page_index, higher_min_page_index;
    struct buddy_page __phys *lower_phys;

    if((void __phys *)page_phys < (void __phys *)buddy_phys)
    {
        lower_min_page_index = min_page_index;
        higher_min_page_index = buddy_min_page_index;
        lower_phys = page_phys;
    }
    else
    {
        lower_min_page_index = buddy_min_page_index;
        higher_min_page_index = min_page_index;
        lower_phys = buddy_phys;
    }

    // Mark the upper page as free
    buddy_bitmap_set(region, higher_min_page_index);
    DEBUG_ASSERT(buddy_bitmap_check(region,higher_min_page_index));
    // Mark the lower page as allocated
    buddy_bitmap_clear(region, lower_min_page_index);
    DEBUG_ASSERT(!buddy_bitmap_check(region,lower_min_page_index));

    // Free the pair of buddies as one larger page
    return buddy_region_free(region, order + 1, lower_phys);

no_buddy:
    // Mark the page as free
    buddy_bitmap_set(region, min_page_index);
    DEBUG_ASSERT(buddy_bitmap_check(region,min_page_index));

    // Add it to the free list for the current order
    return buddy_order_push_page(region, order, page_phys);
}

int
buddy_region_alloc(struct buddy_region *region, order_t order, void __phys **out)
{
    int res;

    dprintk("buddy_region_alloc(region=%p, order=%d)\n", region, order);

    if(order > region->max_order || order < region->min_order)
    {
        printk("buddy_region_alloc: order (%d) is out of range [%d - %d]!\n",
                order,
                region->min_order,
                region->max_order);
        return -ERANGE;
    }

    size_t order_index = order - region->min_order;
    struct buddy_page __phys *buddy_page_phys;
    res = buddy_order_pop_page(region, order, &buddy_page_phys);
    if(res)
    {
        // No pages of this size
        // (Try to allocate a page of the next larger size)

        if(order + 1 > region->max_order)
        {
            // There is not larger size...
            dprintk("buddy_region_alloc: could not allocate page of "
                    "order (%d)\n",
                    order);
            dprintk("buddy_region: amount_free = 0x%llx, "
                    "amount_total = 0x%llx\n",
                    buddy_region_total_free(region),
                    region->pages_bytes);

#ifdef CONFIG_DEBUG_BUDDY_ALLOC
            buddy_region_dump_orders(region, do_printk);
#endif

            return -ENOMEM;
        }

        void __phys *next_order_page_paddr;
        // TODO: Recursion is really dangerous,
        // this can easily cause a stack overflow especially on -O0,
        // rework this.
        res = buddy_region_alloc(region, order + 1, &next_order_page_paddr);
        if(res)
        {
            // Probably just out of memory then...
            return res;
        }

        // Free the higher half of the larger page, and return the lower
        // half

        struct buddy_page __phys *higher_page_phys = next_order_page_paddr + (1ULL << order);
        res = buddy_region_free(region, order, higher_page_phys);
        if(res)
        {
            // We failed to free?
            // (Continue but weird)
        }

        *out = next_order_page_paddr;
        return 0;
    }

    // We have a page of the right size!

    void __phys *page_phys = buddy_page_phys;
    DEBUG_ASSERT(page_phys > region->region_base);
    uintptr_t region_offset = page_phys - region->region_base;
    DEBUG_ASSERT(region_offset < region->region_size);

    uintptr_t pages_offset = region_offset - region->pages_offset;
    size_t min_page_index = pages_offset >> region->min_order;

    *out = page_phys;

    // Mark it as allocated
    DEBUG_ASSERT(min_page_index < (region->pages_bytes >> region->min_order));
    buddy_bitmap_clear(region, min_page_index);

    return 0;
}

int
buddy_region_init(struct buddy_region *region,
                  void __phys *region_base,
                  size_t region_size,
                  order_t min_order,
                  order_t max_order)
{
    dprintk("Initializing buddy_region [%p-%p)\n",
            region_base,
            region_base + region_size);

    const size_t min_page_size = (1ULL << min_order);

    if(min_page_size < sizeof(struct buddy_page))
    {
        // We can't allocate pages this small
        eprintk("Tried to initialize a buddy region with minimum page size "
                "smaller than sizeof(struct buddy_page)!\n");
        return -EINVAL;
    }

    region->region_base = region_base;
    region->region_size = region_size;
    region->min_order = min_order;
    region->max_order = max_order;

    uintptr_t iter_offset = 0;
    void __phys *iter_phys = region->region_base;
    size_t iter_remaining = region->region_size;
#define ADVANCE_ITER(__amt) \
    do { \
        iter_offset += (__amt);\
        iter_phys += (__amt);\
        if(iter_remaining < (__amt)) {\
            return -ENOMEM; \
        }\
        iter_remaining -= (__amt);\
    } while(0)
#define ALIGN_ITER(__order) \
    do { \
        void __phys *aligned = (void __phys *)(((uintptr_t)iter_phys + ((1ULL<<__order)-1))&~((1ULL<<__order)-1));\
        uintptr_t step = (uintptr_t)aligned - (uintptr_t)iter_phys;\
        if(step > 0) {\
            ADVANCE_ITER(step);\
        }\
    } while(0)

    { // Allocate root for the order lists
        ALIGN_ITER(orderof(struct buddy_order));
        region->order_lists_offset = iter_offset;
        region->order_lists_bytes = sizeof(struct buddy_order) * ((region->max_order-region->min_order)+1);
        if(region->order_lists_bytes > region->region_size) {
            return -EINVAL;
        }
        ADVANCE_ITER(region->order_lists_bytes);
    }

    { // Allocate room for the bitmap
        ALIGN_ITER(orderof(unsigned long));
        region->bitmap_offset = iter_offset;
        
        size_t total_bits = iter_remaining * 8;

        // Figure out how many bits we'll need in the bitmap
        size_t bits_per_page_and_bitmap = (min_page_size * 8) + 1;
        size_t num_bitmap_bits = total_bits / bits_per_page_and_bitmap;

        // Figure out how many bytes our bitmap needs to be
        // (We prioritize the bitmap because if a bit doesn't have a page, that's
        // fine, but if a page doesn't have a bit, we have big problems)
        region->bitmap_bytes = BITMAP_SIZE(num_bitmap_bits);

        ADVANCE_ITER(region->bitmap_bytes);
    }

    { // Allocate the "pages" region of actual data to be allocated
        ALIGN_ITER(region->min_order);
        region->pages_offset = iter_offset;
        region->pages_bytes = iter_remaining;
        ADVANCE_ITER(region->pages_bytes);
    }

    // Everything should now be allocated
    DEBUG_ASSERT(iter_remaining == 0);

    // Check for overlap
    DEBUG_ASSERT(region->order_lists_offset + region->order_lists_bytes <= region->bitmap_offset);
    DEBUG_ASSERT(region->bitmap_offset + region->bitmap_bytes <= region->pages_offset);
    DEBUG_ASSERT(region->pages_offset + region->pages_bytes <= region->region_size);

    // Check that everything is aligned
    DEBUG_ASSERT(ptr_orderof(region->region_base + region->order_lists_offset) >= orderof(struct buddy_order));
    DEBUG_ASSERT(ptr_orderof(region->region_base + region->bitmap_offset) >= orderof(unsigned long));
    DEBUG_ASSERT(ptr_orderof(region->region_base + region->pages_offset) >= min_order);

    { // Init all of the buddy lists
        struct buddy_order __phys *order_lists = region->region_base + region->order_lists_offset;
        for(order_t order = region->min_order;
            order <= region->max_order;
            order++)
        {
            size_t index = order - region->min_order;
            struct buddy_order *buddy_order = __va(&order_lists[index]);
            buddy_order->order = order;
            buddy_order->num_pages = 0;
            buddy_order->page_list = 0;
        }
    }
    { // Init the bitmap
        // This is a "free" bitmap, so a zero means everything is allocated currently
        memset_p(region->region_base + region->bitmap_offset, 0, region->bitmap_bytes);
    }

    { // Free all pages
        size_t total_num_pages = region->pages_bytes / min_page_size;

        size_t pages_end_offset = region->pages_offset + (total_num_pages * min_page_size);
        DEBUG_ASSERT(pages_end_offset <= region->region_size);
        for(size_t cur_page_offset = region->pages_offset; cur_page_offset < pages_end_offset;)
        {
            void __phys *addr = region->region_base + cur_page_offset;
            if((uintptr_t)addr & ((1ULL << max_order) - 1) ||
               ((cur_page_offset + (1ULL << max_order)) > pages_end_offset))
            {
                dprintk("freeing page: [%p-%p)\n", addr, addr+min_page_size);
                buddy_region_free(region, min_order, addr);
                cur_page_offset += (1ULL << min_order);
            }
            else
            {
                dprintk("freeing page: [%p-%p)\n", addr, addr+min_page_size);
                buddy_region_free(region, max_order, addr);
                cur_page_offset += (1ULL << max_order);
            }
        }
    }

    dprintk("Finished setting up buddy region (amt-free=0x%lx)\n",
            buddy_region_total_free(region));

    return 0;
}

// page_alloc interface

static int
buddy_page_allocator_alloc(void *state, order_t order, void __phys **addr)
{
    int res;
    struct buddy_region *region = (struct buddy_region *)state;
    res = buddy_region_alloc(region, order, addr);
    if(res)
    {
        return res;
    }
    return 0;
}

static int
buddy_page_allocator_free(void *state, order_t order, void __phys *addr)
{
    struct buddy_region *region = (struct buddy_region *)state;
    return buddy_region_free(region, order, addr);
}

static size_t
buddy_page_allocator_amount_total(void *state)
{
    struct buddy_region *region = (struct buddy_region *)state;
    return buddy_region_total_owned(region);
}

static size_t
buddy_page_allocator_amount_free(void *state)
{
    struct buddy_region *region = (struct buddy_region *)state;
    return buddy_region_total_free(region);
}

static int
buddy_page_allocator_debug_dump(void *state, printk_f *printer)
{
    struct buddy_region *region = (struct buddy_region *)state;

    (*printer)("Buddy Region [%p-%p) (orders[%d-%d])\n",
               (uintptr_t)region->region_base,
               (uintptr_t)(region->region_base + region->region_size),
               (int)region->min_order,
               (int)region->max_order);
//    for(size_t index = 0; index < (region->max_order - region->min_order) + 1;
//        index++)
//    {
//        struct buddy_order *order = &region->order_lists[index];
//        (*printer)("\tOrder[%d] (num-pages=%lu)\n",
//                   (int)order->order,
//                   (ul_t)order->num_pages);
//        DEBUG_ASSERT(ilist_count(&order->page_list) == order->num_pages);
//    }

    return 0;
}

static int
buddy_page_allocator_verify(void *state)
{
    struct buddy_region *region = (struct buddy_region *)state;

//    for(size_t index = 0; index < (region->max_order - region->min_order) + 1;
//        index++)
//    {
//        struct buddy_order *order = &region->order_lists[index];
//        ilist_node_t *page_node;
//        ilist_for_each(page_node, &order->page_list)
//        {
//            struct buddy_page *page =
//                container_of(page_node, struct buddy_page, list_node);
//            ASSERT(page->order == order->order);
//            ASSERT((void *)page >= region->region_base);
//            ASSERT(((void *)page + (1ULL << order->order)) <=
//                   (region->region_base + region->region_size));
//        }
//    }

    return 0;
}

static struct page_allocator_ops buddy_page_allocator_ops = {
    .alloc = buddy_page_allocator_alloc,
    .free = buddy_page_allocator_free,
    .amount_total = buddy_page_allocator_amount_total,
    .amount_free = buddy_page_allocator_amount_free,
    .debug_dump = buddy_page_allocator_debug_dump,
    .verify = buddy_page_allocator_verify,
};

#define BUDDY_REGION_SLAB_BUFFER_SIZE 0x1000
static uint8_t buddy_region_slab_buffer[BUDDY_REGION_SLAB_BUFFER_SIZE];
static struct slab_allocator *buddy_region_slab_allocator = NULL;
DEFINE_LOCAL_THREAD_LOCK(buddy_region_slab_lock);

static int
init_buddy_region_slab_allocator(void)
{
    buddy_region_slab_allocator =
        create_static_slab_allocator(buddy_region_slab_buffer,
                                     BUDDY_REGION_SLAB_BUFFER_SIZE,
                                     sizeof(struct buddy_region),
                                     orderof(struct buddy_region));

    if(buddy_region_slab_allocator == NULL)
    {
        return -ENOMEM;
    }

    return 0;
}
declare_init_desc(static,
                  init_buddy_region_slab_allocator,
                  "Initializing Buddy Region Slab Allocator(s)");

static inline struct buddy_region *
alloc_buddy_region(void)
{
    struct buddy_region *region;
    buddy_region_slab_lock_acquire();
    region = slab_alloc(buddy_region_slab_allocator);
    buddy_region_slab_lock_release();
    return region;
}

__maybe_unused
static inline void
free_buddy_region(struct buddy_region *region)
{
    buddy_region_slab_lock_acquire();
    slab_free(buddy_region_slab_allocator, region);
    buddy_region_slab_lock_release();
}

int
register_buddy_page_allocator(void __phys *phys_base,
                              size_t size,
                              unsigned long flags)
{
    int res;
    printk("Registering Buddy Page Allocator [%p-%p)\n",
            phys_base,
            phys_base + size);

    struct buddy_region *region = alloc_buddy_region();
    if(region == NULL) {
        wprintk("buddy_region_slab_allocator: out of memory!\n");
        return -ENOMEM;
    }

    res = buddy_region_init(region,
                            phys_base,
                            size,
                            PAGE_ALLOC_MIN_ORDER,
                            PAGE_ALLOC_MAX_ORDER);
    if(res)
    {
        return res;
    }

    res = register_page_allocator(&buddy_page_allocator_ops,
                                  (void *)region,
                                  phys_base,
                                  size,
                                  flags);
    if(res)
    {
        return res;
    }

    return 0;
}
