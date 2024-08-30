
#ifdef CONFIG_DEBUG_BUDDY_ALLOC
#define DEBUG
#endif
#include <kanawha/printk.h>

#include <kanawha/string.h>
#include <kanawha/buddy.h>
#include <kanawha/stdint.h>
#include <kanawha/page_alloc.h>
#include <kanawha/errno.h>
#include <kanawha/bitmap.h>
#include <kanawha/mem_flags.h>
#include <kanawha/vmem.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>

struct buddy_page
{
    ilist_node_t list_node;

    // Is this free page the base of the region (making "order" valid)?
    order_t order;
};

struct buddy_order {
    order_t order;
    size_t num_pages;

    ilist_t page_list;
};

struct buddy_region 
{
    void *region_base;
    size_t region_size;

    order_t min_order;
    order_t max_order;

    unsigned long *bitmap;
    size_t bitmap_bytes;

    void *pages_start;
    size_t page_bytes;

    struct buddy_order order_lists[];
};

static inline size_t
buddy_region_num_orders(struct buddy_region *region) {
    return (region->max_order - region->min_order) + 1;
}

static inline size_t
buddy_order_total_free(struct buddy_order *order) {
    return (1ULL<<order->order) * order->num_pages;
}

static inline void
buddy_region_dump_orders(struct buddy_region *region, printk_f *printer)
{
    size_t num_orders = buddy_region_num_orders(region);
    for(size_t i = 0; i < num_orders; i++) {
        struct buddy_order *order = &region->order_lists[i];
        size_t total_free = buddy_order_total_free(order);

        (*printer)("order[%d] -> num_pages=0x%lx, page_size=0x%lx, total_free=0x%lx\n",
                order->order, (unsigned long)order->num_pages, (1UL<<(order->order)), (unsigned long)total_free);
    }
}

size_t
buddy_region_total_free(struct buddy_region *region) {
    size_t size = 0;
    for(order_t i = 0; i < buddy_region_num_orders(region); i++) {
        size += buddy_order_total_free(&region->order_lists[i]);
    }
    return size;
}

static inline int
buddy_order_push_page(struct buddy_order *order, struct buddy_page *page) 
{
    page->order = order->order;
    ilist_push_head(&order->page_list, &page->list_node);
    order->num_pages++;
    /*
    if(order->num_pages == 0) {
        order->list_start = page;
        order->list_end = page;
        order->num_pages = 1;
    } else {
        page->next = order->list_start;
        page->next->prev = page;
        order->list_start = page;
        order->num_pages++;
    }
    */
    return 0;
}

static inline int
buddy_order_pop_page(struct buddy_order *order, struct buddy_page **page) 
{
    if(order->num_pages <= 0) {
        return -EINVAL;
    }

//    struct buddy_page *end = order->list_end;
//    order->list_end = order->list_end->prev;

//    *page = end;

    ilist_node_t *node = ilist_pop_head(&order->page_list);
    *page = container_of(node, struct buddy_page, list_node);

    order->num_pages--;
    return 0;
}

static inline int
buddy_order_remove_page(struct buddy_order *order, struct buddy_page *page) 
{
    if(order->num_pages <= 0) {
        return -EINVAL;
    }

    /*
    if(page == order->list_start) {
        order->list_start = page->next;
    }
    else if(page == order->list_end) {
        order->list_end = page->prev;
    } else {
        page->prev->next = page->next;
        page->next->prev = page->prev;
    }
    */

    ilist_remove(&order->page_list, &page->list_node);

    order->num_pages--;
    return 0;
}

int
buddy_region_free(
        struct buddy_region *region,
        order_t order,
        void *page_addr) 
{
    dprintk("Freeing page: %p of order %d\n", page_addr, order);
    struct buddy_page *page = (struct buddy_page *)page_addr;
    page->order = order;

    order_t order_index = order - region->min_order;

    uintptr_t rel_page_addr = (uintptr_t)page - (uintptr_t)region->pages_start;
    // Note: We aren't necessarily a min_order page but we still care about this index
    //       to access the bitmap
    size_t min_page_index = rel_page_addr >> region->min_order;
 
    struct buddy_page *buddy_page = (struct buddy_page*)((uintptr_t)page_addr ^ (1ULL << order));

    if((uintptr_t)buddy_page < (uintptr_t)region->pages_start) {
        goto no_buddy;
    }

    uintptr_t rel_buddy_page_addr = (uintptr_t)buddy_page - (uintptr_t)region->pages_start;
    size_t buddy_min_page_index = rel_buddy_page_addr >> region->min_order;

    dprintk("page_addr=%p, buddy_page_addr=%p\n",
            page,
            buddy_page);

    dprintk("rel_page_addr=%p, rel_buddy_page_addr=%p\n",
            rel_page_addr,
            rel_buddy_page_addr);
    dprintk("min_page_index=0x%llx, buddy_min_page_index=0x%llx\n",
            (unsigned long long)min_page_index,
            (unsigned long long)buddy_min_page_index);


    void * buddy_page_addr = (void*)buddy_page;

    int can_coalesce = 0;

    if(order + 1 <= region->max_order) {
      if((uintptr_t)buddy_page_addr >= (uintptr_t)region->pages_start 
        && (uintptr_t)buddy_page_addr + (1ULL<<order) <= ((uintptr_t)region->pages_start + region->page_bytes)) {
        if(bitmap_check(region->bitmap, buddy_min_page_index)) {
          if(buddy_page->order == order) {
              can_coalesce = 1;
          } else {
#ifdef CONFIG_DEBUG_BUDDY_ALLOC
              dprintk("bitmap_bytes = 0x%0xlx\n", region->bitmap_bytes);
              dprintk("bitmap[0] = 0x%0lx\n", region->bitmap[0]);
              dprintk("bitmap[1] = 0x%0lx\n", region->bitmap[1]);
              if(buddy_page->order < region->min_order || buddy_page->order > region->max_order) {
                  panic("Found free buddy page with invalid order: %p (order=%d)\n",
                          buddy_page, buddy_page->order);
              }
#endif
              dprintk("Failed to coalesce becuase buddy page is of a different order (%d)\n", buddy_page->order);
          }
        } else {
            dprintk("Failed to coalesce buddy page because buddy is allocated!\n");
        }
      } else {
          dprintk("Failed to coalesce buddy page because buddy is outside of the region!\n");
      }
    } else {
        dprintk("Failed to coalesce buddy page becuase it is the maximum page size\n");
    }

    if(can_coalesce) {

        // Remove our buddy from the order's free list
        buddy_order_remove_page(&region->order_lists[order_index], buddy_page);

        // Figure out which page is the start of the coalesced page (lower)
        size_t lower_min_page_index, higher_min_page_index;
        struct buddy_page *lower_page, *higher_page;

        if((uintptr_t)page < (uintptr_t)buddy_page) {
            lower_min_page_index = min_page_index;
            higher_min_page_index = buddy_min_page_index;
            lower_page = page;
            higher_page = buddy_page;
        } else {
            lower_min_page_index = buddy_min_page_index;
            higher_min_page_index = min_page_index;
            lower_page = buddy_page;
            higher_page = page;
        }

        // Mark the upper page as free
        bitmap_set(region->bitmap, higher_min_page_index);
        // Mark the lower page as allocated
        bitmap_clear(region->bitmap, lower_min_page_index);

        // Free the pair of buddies as one larger page
        return buddy_region_free(region, order+1, (void*)lower_page);
    } 

no_buddy:
    // Mark the page as free
    bitmap_set(region->bitmap, min_page_index);

    // Add it to the free list for the current order
    return buddy_order_push_page(&region->order_lists[order_index], page);
}

int
buddy_region_alloc(
        struct buddy_region *region,
        order_t order,
        void **out) 
{
    int res;

    dprintk("buddy_region_alloc(region=%p, order=%d)\n", region, order);

    if(order > region->max_order || order < region->min_order) {
        dprintk("buddy_region_alloc: order (%d) is out of range [%d - %d]!\n",
                order, region->min_order, region->max_order);
        return -ERANGE;
    }

    size_t order_index = order - region->min_order;
    struct buddy_page *page;
    res = buddy_order_pop_page(&region->order_lists[order_index], &page);
    if(res) {
        // No pages of this size 
        // (Try to allocate a page of the next larger size)

        if(order+1 > region->max_order) {
            // There is not larger size...
            dprintk("buddy_region_alloc: could not allocate page of order (%d)\n", order);
            dprintk("buddy_region: amount_free = 0x%llx, amount_total = 0x%llx\n",
                    buddy_region_total_free(region), region->page_bytes);
#ifdef CONFIG_DEBUG_BUDDY_ALLOC
            buddy_region_dump_orders(region, printk);
#endif
            return -ENOMEM;
        }

        void *next_order_page_paddr;
        res = buddy_region_alloc(region, order+1, &next_order_page_paddr);
        if(res) {
            // Probably just out of memory then...
            return res;
        }

        struct buddy_page *lower_page = (void*)((uintptr_t)next_order_page_paddr);
        struct buddy_page *higher_page = (void*)((uintptr_t)next_order_page_paddr + (1ULL<<order));

        // Free the higher half of the larger page, and return the lower half
        res = buddy_region_free(region, order, (void*)higher_page);
        if(res) {
            // We failed to free?
            // (Continue but weird)
        }

        *out = (void*)lower_page;

        return 0;
    }

    // We have a page of the right size!
    uintptr_t rel_page_addr = (uintptr_t)page - (uintptr_t)region->pages_start;
    size_t min_page_index = rel_page_addr >> region->min_order;

    *out = (void*)page;

    // Mark it as allocated
    bitmap_clear(region->bitmap, min_page_index);

    return 0;
}

int
buddy_region_init(
        void *region_base,
        size_t region_size,
        order_t min_order,
        order_t max_order,
        struct buddy_region **out)
{
    dprintk("Initializing buddy_region at %p of size %lu\n", region_base, region_size);
    order_t num_orders = (max_order-min_order)+1;
    void *region_end = region_base + region_size;

    if((1ULL<<min_order) < sizeof(struct buddy_page)) {
        // We can't allocate pages this small
        eprintk("Tried to initialize a buddy region with minimum page size smaller than sizeof(struct buddy_page)!\n");
        return -EINVAL;
    }

    size_t region_struct_misalignment = __alignof__(struct buddy_region) 
        - ((uintptr_t)region_base % __alignof__(struct buddy_region));
    if(region_struct_misalignment == __alignof__(struct buddy_region)) {
        region_struct_misalignment = 0;
    }

    struct buddy_region *region = (void*)(region_base + region_struct_misalignment);

    // Doesn't account for where we place the bitmap
    void *region_struct_end = (void*)region
                              + sizeof(struct buddy_region)
                              + (sizeof(struct buddy_order) * num_orders);

    if(region_struct_end > region_end) {
        eprintk("Tried to initialize buddy region which is smaller than sizeof(struct buddy_page)!\n");
        return -EINVAL;
    } else {
        // We have enough room so initialize the region header
        // and the order page lists
        region->region_base = region_base;
        region->region_size = region_size;
        region->min_order = min_order;
        region->max_order = max_order;
        for(order_t order = region->min_order; order <= region->max_order; order++) {
            size_t index = order - region->min_order;
            region->order_lists[index].order = order;
            region->order_lists[index].num_pages = 0;
            ilist_init(&region->order_lists[index].page_list);
        }
        *out = region;
    }

    // We technically can succeed no matter what from here on
    // (But we could have a region with zero useful memory)

    uintptr_t useful_memory_bottom = (uintptr_t)region_struct_end;
    uintptr_t useful_memory_top = (uintptr_t)region_end;

    // We need to split this memory into two parts, a bitmap, and pages to be allocated

    // We could put the bitmap either before or after the pages, so put the bitmap 
    // on whichever side has more wasted memory from being misaligned to the minimum page size

    size_t min_page_size = (1ULL<<min_order);

    // How much memory is lost if we align the bottom of the region to the page size?
    size_t bottom_loss = min_page_size - (useful_memory_bottom % min_page_size);
    if(bottom_loss == min_page_size) {
        // We were already aligned to the page size (no loss)
        bottom_loss = 0;
    }

    // How much memory is lost if we align the top of the region to the page size?
    size_t top_loss = useful_memory_top % min_page_size;

    int bitmap_at_bottom = bottom_loss > top_loss;

    // Align our useful memory region
    size_t bottom_alignment;
    size_t top_alignment;

    if(bitmap_at_bottom) {
        bottom_alignment = sizeof(unsigned long);
        top_alignment = min_page_size;
    } else {
        bottom_alignment = min_page_size;
        top_alignment = sizeof(unsigned long);
    }

    if(useful_memory_bottom % bottom_alignment) {
      useful_memory_bottom += bottom_alignment - (useful_memory_bottom % bottom_alignment);
    }
    if(useful_memory_top % top_alignment) {
        useful_memory_top -= useful_memory_top % top_alignment;
    }

    // The actual amount of memory we can use
    if(useful_memory_top <= useful_memory_bottom) {
        // We would have underflowed, this region is too small
        return -ENOMEM;
    }
    size_t useful_memory = useful_memory_top - useful_memory_bottom;

    dprintk("Useful region memory [%p - %p) size=%lu\n",
            useful_memory_bottom,
            useful_memory_top,
            useful_memory);

    size_t total_bits = useful_memory * 8;

    // Figure out how many bits we'll need in the bitmap
    size_t bits_per_page_and_bitmap = (min_page_size * 8) + 1;
    size_t num_bitmap_bits = total_bits / bits_per_page_and_bitmap;

    // Figure out how many bytes our bitmap needs to be
    // (We prioritize the bitmap because if a bit doesn't have a page, that's fine,
    //  but if a page doesn't have a bit, we have big problems)
    region->bitmap_bytes = (num_bitmap_bits / BITS_PER_LONG
        + ((num_bitmap_bits % BITS_PER_LONG) ? 1 : 0))
        * sizeof(unsigned long);

    region->page_bytes = useful_memory - region->bitmap_bytes;
    size_t num_pages = region->page_bytes / min_page_size;
    region->page_bytes = num_pages * min_page_size;

    // Finally assign our bitmap and pages regions accordingly
    if(bitmap_at_bottom) {
        region->bitmap = (unsigned long*)useful_memory_bottom;
        region->pages_start = (void*)(useful_memory_top - region->page_bytes);
    } else {
        region->pages_start = (void*)useful_memory_bottom;
        region->bitmap = (unsigned long*)(useful_memory_top - region->bitmap_bytes);
    }

    dprintk("pages_start = %p, region = %p, region->bitmap = %p, bitmap_bytes = 0x%llx, num_pages = %lu\n", region->pages_start, region, (void*)region->bitmap, (ull_t)region->bitmap_bytes, (ul_t)num_pages);

    // This is a "free" bitmap, so a zero means everything is allocated currently
    // We also assume that the region will be mapped in with an identity mapping for now

    memset((void*)region->bitmap, 0, region->bitmap_bytes);

    // All that's left now is to free all of the pages and let them coalesce together

    void *pages_end = region->pages_start + (num_pages * min_page_size);
    for(void *cur_page = region->pages_start; cur_page < pages_end;) {
        uintptr_t addr = (uintptr_t)cur_page;
        if(addr & ((1ULL<<max_order)-1) || ((cur_page + (1ULL<<max_order)) > pages_end)) {
            dprintk("freeing page: %p\n", cur_page);
            buddy_region_free(region, min_order, cur_page);
            cur_page += (1ULL<<min_order);
        } else {
            dprintk("freeing page: %p\n", cur_page);
            buddy_region_free(region, max_order, cur_page);
            cur_page += (1ULL<<max_order);
        }
    }

    return 0;
}

// page_alloc interface
/*
 * The buddy allocator itself will be operating on virtual addresses,
 * but the page_alloc framework expects physical addresses,
 * these functions handle the conversions
 */

static int
buddy_page_allocator_alloc(void *state, order_t order, paddr_t *addr)
{
    struct buddy_region *region = (struct buddy_region*)state;
    void *vaddr;
    int res = buddy_region_alloc(region, order, &vaddr);
    *addr = __pa((vaddr_t)vaddr);
    return res;
}

static int
buddy_page_allocator_free(void *state, order_t order, paddr_t addr)
{
    struct buddy_region *region = (struct buddy_region*)state;
    return buddy_region_free(region, order, (void*)__va(addr));
}

static size_t
buddy_page_allocator_amount_free(void *state)
{
    struct buddy_region *region = (struct buddy_region*)state;
    return buddy_region_total_free(region);
}

static struct page_allocator_ops buddy_page_allocator_ops = {
    .alloc = buddy_page_allocator_alloc,
    .free = buddy_page_allocator_free,
    .amount_free = buddy_page_allocator_amount_free,
};

int
register_buddy_page_allocator(
        paddr_t phys_base,
        size_t size,
        unsigned long flags)
{
    int res;
    dprintk("Register Buddy Page Allocator VA: %p PA: %p size=0x%lx\n",
            __va(phys_base), phys_base, (unsigned long)size);

    struct buddy_region *region;
    res = buddy_region_init(
            (void*)__va(phys_base),
            size,
            PAGE_ALLOC_MIN_ORDER,
            PAGE_ALLOC_MAX_ORDER,
            &region);
    if(res) {
        return res;
    }

    res = register_page_allocator(
            &buddy_page_allocator_ops,
            (void*)region,
            phys_base,
            size,
            flags);
    if(res) {
        return res;
    }

    return 0;
}

