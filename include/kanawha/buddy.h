#ifndef __KANAWHA__BUDDY_H__
#define __KANAWHA__BUDDY_H__

#include <kanawha/stdint.h>
#include <kanawha/printk.h>
#include <kanawha/page_alloc.h>

struct buddy_region;

/*
 * Buddy Region Allocator
 *
 * (Not currently thread safe)
 * (The region needs to stay identity mapped while it is being used)
 *
 */

// Initialize a region of usable memory as a buddy allocator
int buddy_region_init(
        void *start,
        size_t size,
        unsigned int min_order,
        unsigned int max_order,
        struct buddy_region **region);

// Allocate a page of size (1<<order) from the buddy region
int buddy_region_alloc(
        struct buddy_region *region,
        unsigned int order,
        void **page_addr);

// Free a page of size (1<<order) previously allocated from the buddy region
int buddy_region_free(
        struct buddy_region *region,
        unsigned int order,
        void *page_addr);

// Get the total amount of free memory in the buddy region
size_t buddy_region_total_free(struct buddy_region *region);

// Print out some debug information about the buddy region
void buddy_region_debug_print(struct buddy_region *region, printk_f *printer);

/*
 * Buddy Page Allocator
 *
 * Used for initializing a buddy region with the page_alloc subsystem 
 */

int
register_buddy_page_allocator(
        paddr_t phys_base,
        size_t size,
        unsigned long flags);

#endif
