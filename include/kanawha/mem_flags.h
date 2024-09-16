#ifndef __KANAWHA__MEM_FLAGS_H__
#define __KANAWHA__MEM_FLAGS_H__

#include <kanawha/stdint.h>
#include <kanawha/printk.h>
#include <kanawha/spinlock.h>

struct mem_flags_entry {
    uintptr_t base;
    size_t size;
    unsigned long flags;
};

struct mem_flags {
    size_t max_entries;
    size_t num_entries;
    spinlock_t lock;
    struct mem_flags_entry *entries;
};

int mem_flags_clear_all(struct mem_flags *map, unsigned long flags);

int
mem_flags_get_overlapping_regions(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        size_t *base_entry_index,
        size_t *num_entries);

int 
mem_flags_set_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long to_set);

int 
mem_flags_clear_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long to_clear);

// Returns 0 for flags if addr is not found in the map
// Else returns the flags of addr
unsigned long
mem_flags_read(
        struct mem_flags *map,
        uintptr_t addr);

// Find a region aligned to "align_order" of size "size"
// with flags matching "must_be_*" and modify the flags
// with "to_set" and "to_clear"
int
mem_flags_find_and_reserve(
        struct mem_flags *map,
        size_t size,
        order_t align_order,
        unsigned long must_be_set,
        unsigned long must_be_clear,
        unsigned long to_set,
        unsigned long to_clear,
        uintptr_t *base_out);

void
mem_flags_print(
        struct mem_flags *map,
        printk_f *printer,
        void(*flag_printer)(printk_f *printer, unsigned long flags));

/*
 * Physical Memory Flags
 */

#define PHYS_MEM_FLAGS_AVAIL      (1UL<<0)
#define PHYS_MEM_FLAGS_FW_RESV    (1UL<<1)
#define PHYS_MEM_FLAGS_KERNEL     (1UL<<2)
#define PHYS_MEM_FLAGS_RAM        (1UL<<3)
#define PHYS_MEM_FLAGS_SAVE       (1UL<<4)
#define PHYS_MEM_FLAGS_DEFECT     (1UL<<5)
#define PHYS_MEM_FLAGS_FW_IGNORE  (1UL<<6)
#define PHYS_MEM_FLAGS_PAGE_ALLOC (1UL<<7)
#define PHYS_MEM_FLAGS_16_BIT     (1UL<<8)
#define PHYS_MEM_FLAGS_32_BIT     (1UL<<9)

int phys_mem_flags_dump(void);
struct mem_flags * get_phys_mem_flags(void);

/*
 * Virtual Memory Flags 
 */
#define VIRT_MEM_FLAGS_NONCANON (1UL<<0)
#define VIRT_MEM_FLAGS_HIGHMEM  (1UL<<1)
#define VIRT_MEM_FLAGS_AVAIL    (1UL<<2)
#define VIRT_MEM_FLAGS_HEAP     (1UL<<3)
#define VIRT_MEM_FLAGS_MMIO     (1UL<<4)
#define VIRT_MEM_FLAGS_PERCPU   (1UL<<5)

int virt_mem_flags_dump(void);
struct mem_flags * get_virt_mem_flags(void);

#endif
