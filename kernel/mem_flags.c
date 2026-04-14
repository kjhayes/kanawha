
#include <kanawha/buddy.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>

#define MEM_FLAGS_FLAG_STATIC_BUFFER (1UL<<0)

int
mem_flags_init(
        struct mem_flags *mem_flags,
        unsigned long initial_flags,
        size_t static_buflen,
        struct mem_flags_entry *static_buffer)
{
    int res;

    spinlock_init(&mem_flags->lock);
    mem_flags->max_entries = static_buflen;
    mem_flags->num_entries = 0;
    mem_flags->flags = 0;

    if(static_buffer != NULL) {
        mem_flags->entries = static_buffer;
        mem_flags->flags |= MEM_FLAGS_FLAG_STATIC_BUFFER;
    } else {
        mem_flags->entries = kmalloc(sizeof(struct mem_flags_entry) * mem_flags->max_entries, KM_KERNEL);

        if(mem_flags->entries == NULL) {
            return -ENOMEM;
        }
    }

    res = mem_flags_clear_all(mem_flags, initial_flags);
    if(res)
    {
        return res;
    }

    return 0;
}

int
mem_flags_deinit(
        struct mem_flags *mem_flags)
{
    if(!(mem_flags->flags & MEM_FLAGS_FLAG_STATIC_BUFFER))
    {
        kfree(mem_flags->entries);
        mem_flags->entries = NULL;
        mem_flags->flags &= ~MEM_FLAGS_FLAG_STATIC_BUFFER;
    }

    return 0;
}

static int
__mem_flags_get_overlapping(struct mem_flags *map,
                            uintptr_t base,
                            size_t *base_index)
{
    size_t base_entry_index = -1;
    size_t num_found = 0;

    for(size_t i = 0; i < map->num_entries; i++)
    {
        struct mem_flags_entry *cur_entry = &map->entries[i];
        uintptr_t cur_end = cur_entry->base + cur_entry->size;

        if(base >= cur_end)
        {
            continue;
        }
        else if(base < cur_entry->base)
        {
            break;
        }
        else
        {
            // Overlapping
            if(base_entry_index == -1)
            {
                base_entry_index = i;
            }
            num_found++;
        }
    }

    if(num_found != 1)
    {
        eprintk("Failed to find mem_flags entry of offset %p\n", base);
        return -EINVAL;
    }

    *base_index = base_entry_index;
    return 0;
}

int
mem_flags_get_overlapping_regions(struct mem_flags *map,
                                  uintptr_t base,
                                  size_t size,
                                  size_t *base_index,
                                  size_t *num_entries)
{
    uintptr_t end = base + size;

    size_t base_entry_index = -1;
    size_t num_found = 0;

    spin_lock(&map->lock);

    for(size_t i = 0; i < map->num_entries; i++)
    {
        struct mem_flags_entry *cur_entry = &map->entries[i];
        uintptr_t cur_end = cur_entry->base + cur_entry->size;

        if(base >= cur_end)
        {
            continue;
        }
        else if(cur_entry->base >= end)
        {
            break;
        }
        else
        {
            // Overlapping
            if(base_entry_index == -1)
            {
                base_entry_index = i;
            }
            num_found++;
        }
    }

    spin_unlock(&map->lock);

    *base_index = base_entry_index;
    *num_entries = num_found;

    return 0;
}

int
mem_flags_clear_all(struct mem_flags *map, unsigned long empty_flags)
{
    spin_lock(&map->lock);
    if(map->max_entries <= 0)
    {
        return -EINVAL;
    }

    map->num_entries = 1;
    map->entries[0].size = -1;
    map->entries[0].base = 0;
    map->entries[0].flags = empty_flags;
    spin_unlock(&map->lock);
    return 0;
}

static int
__mem_flags_split_at(struct mem_flags *map, uintptr_t base)
{
    size_t room_left = map->max_entries - map->num_entries;
    if(room_left == 0)
    {
        return -ENOMEM;
    }

    int res;
    size_t index;
    res = __mem_flags_get_overlapping(map, base, &index);
    if(res)
    {
        return res;
    }

    struct mem_flags_entry *entry = &map->entries[index];
    if(entry->base == base)
    {
        return 0;
    }
    else if(entry->base + entry->size == base)
    {
        return 0;
    }

    unsigned long flags = entry->flags;
    uintptr_t original_base = entry->base;
    size_t original_size = entry->size;

    size_t entries_after = map->num_entries - index;
    memmove(&map->entries[index + 1],
            &map->entries[index],
            sizeof(struct mem_flags_entry) * entries_after);
    struct mem_flags_entry *bottom = &map->entries[index];
    struct mem_flags_entry *top = &map->entries[index + 1];

    bottom->flags = flags;
    top->flags = flags;

    bottom->base = original_base;
    bottom->size = base - original_base;

    top->base = original_base + bottom->size;
    top->size = original_size - bottom->size;

    dprintk("Split [%p - %p) into [%p - %p) and [%p - %p)\n",
            original_base,
            original_base + original_size,
            bottom->base,
            bottom->base + bottom->size,
            top->base,
            top->base + top->size);

    map->num_entries++;

    return 0;
}

static int
__mem_flags_change_flags(struct mem_flags *map,
                         uintptr_t base,
                         size_t size,
                         unsigned long flags_input,
                         unsigned long (*flag_func)(unsigned long flags,
                                                    unsigned long flags_input))
{
    int res = 0;
    size_t index;

__recurse:
    if(size <= 0)
    {
        goto exit;
    }

    res = __mem_flags_get_overlapping(map, base, &index);
    if(res)
    {
        return res;
    }

    if(map->entries[index].base == base)
    {
        if(map->entries[index].size <= size)
        {
            // Apply our flag func, we cover the region entirely
            map->entries[index].flags =
                (*flag_func)(map->entries[index].flags, flags_input);

            size -= map->entries[index].size;
            base += map->entries[index].size;

            if(size > 0)
            {
                goto __recurse;
            }
            else
            {
                goto exit;
            }
        }
        else
        {
            // We need to split the region at our end
            dprintk("Splitting Flags End\n");
            res = __mem_flags_split_at(map, map->entries[index].base + size);
            if(res)
            {
                return res;
            }

            goto __recurse;
        }
    }
    else
    {
        // We need to split the region at our base
        dprintk("Splitting Flags Base base = %p, region_base = %p\n",
                base,
                map->entries[index].base);
        res = __mem_flags_split_at(map, base);
        if(res)
        {
            return res;
        }

        goto __recurse;
    }

exit:

    // Merge any adjacent regions with the same flags
    if(map->num_entries > 0)
    {
        // Reverse order so we can coalesce more than one at a time
        for(size_t iplus = map->num_entries - 1; iplus > 0; iplus--)
        {

            size_t i = iplus - 1;

            struct mem_flags_entry *lower = &map->entries[i];
            struct mem_flags_entry *upper = &map->entries[i + 1];

            if(lower->flags == upper->flags)
            {
                lower->size += upper->size;
                upper->size = 0;
            }
        }

        // Now we need to remove any size zero entries and compact the map
        size_t gap_size =
            0; // (also equal to the number of entries we are removing)
        for(size_t i = 0; i < map->num_entries; i++)
        {
            struct mem_flags_entry *cur = &map->entries[i];
            if(cur->size == 0)
            {
                gap_size++;
                continue;
            }

            if(gap_size > 0)
            {
                map->entries[i - gap_size] = map->entries[i];
            }
        }
        map->num_entries -= gap_size;
    }

    return 0;
}

static inline unsigned long
__mem_flags_set_flags_func(unsigned long flags, unsigned long to_set)
{
    return flags | to_set;
}

static inline unsigned long
__mem_flags_clear_flags_func(unsigned long flags, unsigned long to_clear)
{
    // printk("clear_flags 0x%x -> 0x%x\n",
    //         flags, flags & ~to_clear);
    return flags & ~to_clear;
}

static int
__mem_flags_set_flags(struct mem_flags *map,
                      uintptr_t base,
                      size_t size,
                      unsigned long to_set)
{
    return __mem_flags_change_flags(map,
                                    base,
                                    size,
                                    to_set,
                                    __mem_flags_set_flags_func);
}

int
mem_flags_set_flags(struct mem_flags *map,
                    uintptr_t base,
                    size_t size,
                    unsigned long to_set)
{
    int res;
    spin_lock(&map->lock);
    res = __mem_flags_set_flags(map, base, size, to_set);
    spin_unlock(&map->lock);
    return res;
}

static int
__mem_flags_clear_flags(struct mem_flags *map,
                        uintptr_t base,
                        size_t size,
                        unsigned long to_clear)
{
    return __mem_flags_change_flags(map,
                                    base,
                                    size,
                                    to_clear,
                                    __mem_flags_clear_flags_func);
}

int
mem_flags_clear_flags(struct mem_flags *map,
                      uintptr_t base,
                      size_t size,
                      unsigned long to_clear)
{
    int res;
    spin_lock(&map->lock);
    res = __mem_flags_clear_flags(map, base, size, to_clear);
    spin_unlock(&map->lock);
    return res;
}

struct mem_flags_entry *
__mem_flags_read_entry(struct mem_flags *map, uintptr_t addr)
{
    for(size_t i = 0; i < map->num_entries; i++)
    {
        struct mem_flags_entry *entry = &map->entries[i];
        uintptr_t end = entry->base + entry->size;
        if(entry->base <= addr && addr < end)
        {
            return entry;
        }
    }
    return NULL;
}

unsigned long
mem_flags_read(struct mem_flags *map, uintptr_t addr)
{
    struct mem_flags_entry *entry;
    spin_lock(&map->lock);
    entry = __mem_flags_read_entry(map, addr);
    if(entry == NULL)
    {
        spin_unlock(&map->lock);
        return 0;
    }
    spin_unlock(&map->lock);
    return entry->flags;
}

int
mem_flags_find_and_reserve(struct mem_flags *map,
                           size_t size,
                           order_t align_order,
                           unsigned long must_be_set,
                           unsigned long must_be_clear,
                           unsigned long to_set,
                           unsigned long to_clear,
                           uintptr_t *base_out)
{
    int res;
    spin_lock(&map->lock);
    for(size_t i = 0; i < map->num_entries; i++)
    {
        struct mem_flags_entry *entry = &map->entries[i];
        if(entry->size < size)
        {
            continue;
        }
        uintptr_t align_size = (1ULL << align_order);
        uintptr_t align_mask = (1ULL << align_order) - 1;
        uintptr_t align_offset =
            (align_size - (entry->base & align_mask)) & align_mask;

        if(entry->size - align_offset < size)
        {
            continue;
        }

        // We can fit, check the flags
        uintptr_t base = entry->base + align_offset;

        if(entry->flags & must_be_clear)
        {
            continue;
        }

        if((entry->flags & must_be_set) != must_be_set)
        {
            continue;
        }

        // Can fit and we have the right flags,
        // set the flags and return this region

        res = __mem_flags_set_flags(map, base, size, to_set);
        if(res)
        {
            spin_unlock(&map->lock);
            return res;
        }
        res = __mem_flags_clear_flags(map, base, size, to_clear);
        if(res)
        {
            spin_unlock(&map->lock);
            return res;
        }

        spin_unlock(&map->lock);
        *base_out = base;
        return 0;
    }
    spin_unlock(&map->lock);
    return -ENOMEM;
}

int
mem_flags_check_region(struct mem_flags *map,
                       uintptr_t base,
                       size_t size,
                       unsigned long must_be_set,
                       unsigned long must_be_clear)
{
    int res;
    size_t base_index;
    size_t num_indices;
    res = mem_flags_get_overlapping_regions(map,
                                            base,
                                            size,
                                            &base_index,
                                            &num_indices);
    if(res)
    {
        return res;
    }

    for(size_t i = base_index; i < base_index + num_indices; i++)
    {
        struct mem_flags_entry *entry = &map->entries[i];
        if((entry->flags & must_be_set) != must_be_set)
        {
            return -EEXIST;
        }
        if((entry->flags & must_be_clear) != 0)
        {
            return -EEXIST;
        }
    }

#undef BUFLEN
    return 0;
}

void
mem_flags_print(struct mem_flags *map,
                printk_f *printer,
                void (*flag_printer)(printk_f *printer, unsigned long flags))
{
    spin_lock(&map->lock);
    for(size_t i = 0; i < map->num_entries; i++)
    {
        struct mem_flags_entry *entry = &map->entries[i];
        uintptr_t end = entry->base + entry->size;
        (*printer)("[%p - %p) size=%lx ",
                   entry->base,
                   end,
                   (unsigned long)entry->size);
        (*flag_printer)(printer, (unsigned long)entry->flags);
        (*printer)("\n");
    }
    spin_unlock(&map->lock);
}

/*
 * Physical Memory
 */

#define MAX_PHYS_MEM_FLAGS_ENTRIES 256
static struct mem_flags __phys_mem_flags = {0};
static struct mem_flags_entry
    __phys_mem_flags_buffer[MAX_PHYS_MEM_FLAGS_ENTRIES];

struct mem_flags *
get_phys_mem_flags(void)
{
    return &__phys_mem_flags;
}

static int
phys_mem_flags_static_init(void)
{
    int res;

    res = mem_flags_init(
            &__phys_mem_flags,
            PHYS_MEM_FLAGS_AVAIL,
            MAX_PHYS_MEM_FLAGS_ENTRIES,
            __phys_mem_flags_buffer);
    if(res) {
        return res;
    }

    // Mark our 32-bit and 16-bit physical addresses
    res = mem_flags_set_flags(&__phys_mem_flags,
                              0,
                              0x10000,
                              PHYS_MEM_FLAGS_16_BIT);
    if(res)
    {
        return res;
    }

    res = mem_flags_set_flags(&__phys_mem_flags,
                              0,
                              0x100000000,
                              PHYS_MEM_FLAGS_32_BIT);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
phys_mem_flags_reserve_kernel(void)
{
    int res;

    void __phys *phys_start = arch_kernel_phys_start();
    size_t size = arch_kernel_phys_size();

    printk("Kernel Physical Region [%p - %p)\n", phys_start, phys_start + size);

    res = mem_flags_set_flags(get_phys_mem_flags(),
                              (uintptr_t)phys_start,
                              size,
                              PHYS_MEM_FLAGS_KERNEL);

    if(res)
    {
        return res;
    }

    res = mem_flags_clear_flags(get_phys_mem_flags(),
                                (uintptr_t)arch_kernel_phys_start(),
                                arch_kernel_phys_size(),
                                PHYS_MEM_FLAGS_AVAIL);

    if(res)
    {
        return res;
    }

    return 0;
}

static void
phys_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    if(flags & PHYS_MEM_FLAGS_AVAIL)
    {
        (*printer)("[AVAIL]");
    }
    if(flags & PHYS_MEM_FLAGS_FW_RESV)
    {
        (*printer)("[FW_RESV]");
    }
    if(flags & PHYS_MEM_FLAGS_KERNEL)
    {
        (*printer)("[KERNEL]");
    }
    if(flags & PHYS_MEM_FLAGS_RAM)
    {
        (*printer)("[RAM]");
    }
    if(flags & PHYS_MEM_FLAGS_SAVE)
    {
        (*printer)("[SAVE]");
    }
    if(flags & PHYS_MEM_FLAGS_DEFECT)
    {
        (*printer)("[DEFECT]");
    }
    if(flags & PHYS_MEM_FLAGS_FW_IGNORE)
    {
        (*printer)("[FW_IGNORE]");
    }
    if(flags & PHYS_MEM_FLAGS_PAGE_ALLOC)
    {
        (*printer)("[PAGE_ALLOC]");
    }
    if(flags & PHYS_MEM_FLAGS_16_BIT)
    {
        (*printer)("[16]");
    }
    if(flags & PHYS_MEM_FLAGS_32_BIT)
    {
        (*printer)("[32]");
    }
    if(flags & PHYS_MEM_FLAGS_MMIO)
    {
        (*printer)("[MMIO]");
    }
}

int
phys_mem_flags_dump(void)
{
    printk("=== Physical Memory Flags ===\n");
    mem_flags_print(get_phys_mem_flags(), do_printk, phys_mem_flags_printer);
    printk("=============================\n");
    return 0;
}

declare_init_desc(static,
                  phys_mem_flags_static_init,
                  "Setting Up Physical Memory Map");
declare_init_desc(post_mem_flags,
                  phys_mem_flags_reserve_kernel,
                  "Reserving the Kernel in Physical Memory");

/*
 * Virtual Memory
 */
#define MAX_VIRT_MEM_FLAGS_ENTRIES 256
static struct mem_flags __virt_mem_flags = {0};
static struct mem_flags_entry
    __virt_mem_flags_buffer[MAX_VIRT_MEM_FLAGS_ENTRIES];

struct mem_flags *
get_virt_mem_flags(void)
{
    return &__virt_mem_flags;
}

static int
virt_mem_flags_static_init(void)
{
    int res;

    res = mem_flags_init(
            &__virt_mem_flags,
            VIRT_MEM_FLAGS_NONCANON
           |VIRT_MEM_FLAGS_AVAIL,
            MAX_VIRT_MEM_FLAGS_ENTRIES,
            __virt_mem_flags_buffer);
    if(res) {
        return res;
    }

    printk("Marking all of virtual memory available\n");
    return 0;
}

static void
virt_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    if(flags & VIRT_MEM_FLAGS_NONCANON)
    {
        (*printer)("[NONCANON]");
    }
    if(flags & VIRT_MEM_FLAGS_HIGHMEM)
    {
        (*printer)("[HIGH]");
    }
    if(flags & VIRT_MEM_FLAGS_AVAIL)
    {
        (*printer)("[AVAIL]");
    }
    if(flags & VIRT_MEM_FLAGS_HEAP)
    {
        (*printer)("[HEAP]");
    }
    if(flags & VIRT_MEM_FLAGS_MMIO)
    {
        (*printer)("[MMIO]");
    }
    if(flags & VIRT_MEM_FLAGS_PERCPU)
    {
        (*printer)("[PERCPU]");
    }
}

int
virt_mem_flags_dump(void)
{
    printk("=== Virtual Memory Flags ===\n");
    mem_flags_print(get_virt_mem_flags(), do_printk, virt_mem_flags_printer);
    printk("============================\n");
    return 0;
}
declare_init_desc(static,
                  virt_mem_flags_static_init,
                  "Initializing Virtual Memory Map");

static int
mem_flags_dump(void)
{
    phys_mem_flags_dump();
    virt_mem_flags_dump();
    return 0;
}
declare_init_desc(page_alloc, mem_flags_dump, "Memory Map Dump");

// Freeing Memory

static int
free_phys_mem(void)
{
    int res;
    struct mem_flags *map = get_phys_mem_flags();

    int freed_something;
    do
    {
        freed_something = 0;

        for(size_t i = 0; i < map->num_entries; i++)
        {
            struct mem_flags_entry *entry = &map->entries[i];
            if(!(entry->flags & PHYS_MEM_FLAGS_AVAIL))
            {
                continue;
            }
            if(!(entry->flags & PHYS_MEM_FLAGS_RAM))
            {
                continue;
            }
            DEBUG_ASSERT(!(entry->flags & PHYS_MEM_FLAGS_PAGE_ALLOC));

            unsigned long cur_flags = entry->flags;
            void *cur_base = (void *)entry->base;
            size_t cur_size = (size_t)entry->size;
            void *cur_end = (void *)(cur_base + cur_size);

            // Free this region
            dprintk("Registering Buddy Allocator for region [%p - %p)\n",
                    cur_base,
                    cur_end);

            unsigned long page_alloc_flags = 0;
            if(cur_flags & PHYS_MEM_FLAGS_16_BIT)
            {
                page_alloc_flags |= PAGE_ALLOC_16BIT;
            }
            if(cur_flags & PHYS_MEM_FLAGS_32_BIT)
            {
                page_alloc_flags |= PAGE_ALLOC_32BIT;
            }

            res = register_buddy_page_allocator((void __phys *)cur_base,
                                                cur_size,
                                                page_alloc_flags);
            if(res)
            {
                eprintk("Failed to register buddy allocator for "
                        "region [%p - "
                        "%p) (err=%s)\n",
                        cur_base,
                        cur_end,
                        errnostr(res));
                continue;
            }

            res = mem_flags_clear_flags(map,
                                        (uintptr_t)cur_base,
                                        cur_size,
                                        PHYS_MEM_FLAGS_AVAIL);
            if(res)
            {
                eprintk("Failed to mark page_alloc region as "
                        "unavailable in "
                        "physical memory map!\n");
                return res;
            }

            res = mem_flags_set_flags(map,
                                      (uintptr_t)cur_base,
                                      cur_size,
                                      PHYS_MEM_FLAGS_PAGE_ALLOC);
            if(res)
            {
                eprintk("Failed to mark page_alloc region as "
                        "allocatable in "
                        "physical memory map!\n");
                return res;
            }

            printk("Registered Buddy Allocator for region [%p - %p)\n",
                   cur_base,
                   cur_end);
            freed_something = 1;
            break;
        }
    } while(freed_something);

    printk("Finished freeing physical memory!\n");

    return 0;
}
declare_init_desc(page_alloc,
                  free_phys_mem,
                  "Freeing Available Physical Memory");
