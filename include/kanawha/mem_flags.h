#ifndef __KANAWHA__MEM_FLAGS_H__
#define __KANAWHA__MEM_FLAGS_H__

#include <kanawha/pointer.h>
#include <kanawha/printk.h>
#include <kanawha/spinlock.h>
#include <kanawha/types.h>

void __phys *
arch_kernel_phys_start(void);
size_t
arch_kernel_phys_size(void);

void *
arch_kernel_virt_start(void);
size_t
arch_kernel_virt_size(void);

struct mem_flags_entry
{
    uintptr_t base;
    size_t size;
    unsigned long flags;
};

struct mem_flags
{
    size_t max_entries;
    size_t num_entries;
    spinlock_t lock;
    struct mem_flags_entry *entries;

    unsigned long flags;
};

int
mem_flags_init(struct mem_flags *mem_flags,
               unsigned long initial_flags,
               size_t static_buflen,
               struct mem_flags_entry *static_buffer);

int
mem_flags_deinit(struct mem_flags *mem_flags);

int
mem_flags_clear_all(struct mem_flags *map, unsigned long flags);

int
mem_flags_get_overlapping_regions(struct mem_flags *map,
                                  uintptr_t base,
                                  size_t size,
                                  size_t *base_entry_index,
                                  size_t *num_entries);

int
mem_flags_set_flags(struct mem_flags *map,
                    uintptr_t base,
                    size_t size,
                    unsigned long to_set);

int
mem_flags_clear_flags(struct mem_flags *map,
                      uintptr_t base,
                      size_t size,
                      unsigned long to_clear);

// Returns 0 for flags if addr is not found in the map
// Else returns the flags of addr
unsigned long
mem_flags_read(struct mem_flags *map, uintptr_t addr);

// Find a region aligned to "align_order" of size "size"
// with flags matching "must_be_*" and modify the flags
// with "to_set" and "to_clear"
int
mem_flags_find_and_reserve(struct mem_flags *map,
                           size_t size,
                           order_t align_order,
                           unsigned long must_be_set,
                           unsigned long must_be_clear,
                           unsigned long to_set,
                           unsigned long to_clear,
                           uintptr_t *base_out);

// Ensure that the given region is mapped properly
// Returns 0 if the constraints are met, negative errno otherwise
int
mem_flags_check_region(struct mem_flags *map,
                       uintptr_t base,
                       size_t size,
                       unsigned long must_be_set,
                       unsigned long must_be_clear);

// Combines "check_region", followed by "set_flags, clear_flags"
int
mem_flags_reserve_region(struct mem_flags *map,
                         uintptr_t base,
                         size_t size,
                         unsigned long must_be_set,
                         unsigned long must_be_clear,
                         unsigned long to_set,
                         unsigned long to_clear);

// Get the "size" of regions matching a description
ssize_t
mem_flags_size_matching(
        struct mem_flags *map,
        unsigned long must_be_set,
        unsigned long must_be_clear);

int
mem_flags_print(struct mem_flags *map,
                struct printer *printer,
                void (*flag_printer)(struct printer *printer, unsigned long flags));

/*
 * Physical Memory Flags
 */

#define PHYS_MEM_FLAGS_XLIST(X,...)\
X(AVAIL,       0,   ##__VA_ARGS__)\
X(FW_RESV,     1,   ##__VA_ARGS__)\
X(KERNEL,      2,   ##__VA_ARGS__)\
X(RAM,         3,   ##__VA_ARGS__)\
X(SAVE,        4,   ##__VA_ARGS__)\
X(DEFECT,      5,   ##__VA_ARGS__)\
X(FW_IGNORE,   6,   ##__VA_ARGS__)\
X(PAGE_ALLOC,  7,   ##__VA_ARGS__)\
X(16_BIT,      8,   ##__VA_ARGS__)\
X(32_BIT,      9,   ##__VA_ARGS__)\
X(MMIO,        10,  ##__VA_ARGS__)\

enum {
#define XCASE(__NAME, __BIT_OFFSET, ...)\
    PHYS_MEM_FLAGS_##__NAME = (1UL<<(__BIT_OFFSET)),
    PHYS_MEM_FLAGS_XLIST(XCASE)
#undef XCASE
};

int
phys_mem_flags_dump(struct printer *printer);
struct mem_flags *
get_phys_mem_flags(void);

/*
 * Virtual Memory Flags
 */

#define VIRT_MEM_FLAGS_XLIST(X,...)\
X(NONCANON,  0, ##__VA_ARGS__)\
X(HIGHMEM,   1, ##__VA_ARGS__)\
X(AVAIL,     2, ##__VA_ARGS__)\
X(HEAP,      3, ##__VA_ARGS__)\
X(MMIO,      4, ##__VA_ARGS__)\
X(PERCPU,    5, ##__VA_ARGS__)\
X(KUSER,     6, ##__VA_ARGS__)\
X(KERNEL,    7, ##__VA_ARGS__)\

enum {
#define XCASE(__NAME, __BIT_OFFSET, ...)\
    VIRT_MEM_FLAGS_##__NAME = (1UL<<(__BIT_OFFSET)),
    VIRT_MEM_FLAGS_XLIST(XCASE)
#undef XCASE
};

int
virt_mem_flags_dump(struct printer *printer);
struct mem_flags *
get_virt_mem_flags(void);

#endif
