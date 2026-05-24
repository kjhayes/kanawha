#ifndef __KANAWHA__BUDDY_H__
#define __KANAWHA__BUDDY_H__

#include <kanawha/page_alloc.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>

struct buddy_region;

/*
 * Buddy Region Allocator
 *
 * (Not currently thread safe)
 *
 */

// Initialize a region of usable memory as a buddy allocator
int
buddy_region_init(struct buddy_region *region,
                  void __phys *start,
                  size_t size,
                  unsigned int min_order,
                  unsigned int max_order);

// Allocate a page of size (1<<order) from the buddy region
int
buddy_region_alloc(struct buddy_region *region,
                   unsigned int order,
                   void __phys **page_addr);

// Free a page of size (1<<order) previously allocated from the buddy region
int
buddy_region_free(struct buddy_region *region,
                  unsigned int order,
                  void __phys *page_addr);

// Get the total amount of free memory in the buddy region
size_t
buddy_region_total_free(struct buddy_region *region);

// Print out some debug information about the buddy region
void
buddy_region_debug_print(struct buddy_region *region, printk_f *printer);

/*
 * Buddy Page Allocator
 *
 * Used for initializing a buddy region with the page_alloc subsystem
 */

int
register_buddy_page_allocator(void __phys *phys_base,
                              size_t size,
                              unsigned long flags);

#endif
