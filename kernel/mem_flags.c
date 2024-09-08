
#include <kanawha/mem_flags.h>
#include <kanawha/string.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>
#include <kanawha/buddy.h>
#include <kanawha/vmem.h>

int
mem_flags_get_overlapping(
        struct mem_flags *map,
        uintptr_t base,
        size_t *base_index)
{
    size_t base_entry_index = -1;
    size_t num_found = 0;

    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *cur_entry = &map->entries[i];
        uintptr_t cur_end = cur_entry->base + cur_entry->size;

        if(base >= cur_end) {
            continue;
        } else if(base < cur_entry->base) {
            break;
        } else {
            // Overlapping
            if(base_entry_index == -1) {
                base_entry_index = i;
            }
            num_found++;
        }
    }

    if(num_found != 1) {
        eprintk("Failed to find mem_flags entry of offset %p\n", base);
        return -EINVAL;
    }

    *base_index = base_entry_index;
    return 0;

}

int
mem_flags_get_overlapping_regions(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        size_t *base_index,
        size_t *num_entries)
{
    uintptr_t end = base + size;

    size_t base_entry_index = -1;
    size_t num_found = 0;

    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *cur_entry = &map->entries[i];
        uintptr_t cur_end = cur_entry->base + cur_entry->size;

        if(base >= cur_end) {
            continue;
        } else if(cur_entry->base >= end) {
            break;
        } else {
            // Overlapping
            if(base_entry_index == -1) {
                base_entry_index = i;
            }
            num_found++;
        }
    }

    *base_index = base_entry_index;
    *num_entries = num_found;
    return 0;
}

int mem_flags_clear_all(struct mem_flags *map, unsigned long empty_flags) 
{
    if(map->max_entries <= 0) {
        return -EINVAL;
    }
    
    map->num_entries = 1;
    map->entries[0].size = -1;
    map->entries[0].base = 0;
    map->entries[0].flags = empty_flags;
    return 0;
}

static int
__mem_flags_split_at(
        struct mem_flags *map,
        uintptr_t base)
{
    size_t room_left = map->max_entries - map->num_entries;
    if(room_left == 0) {
        return -ENOMEM;
    }

    int res;
    size_t index;
    res = mem_flags_get_overlapping(map, base, &index);
    if(res) {
        return res;
    }

    struct mem_flags_entry *entry = &map->entries[index];
    if(entry->base == base) {
        return 0;
    }
    else if(entry->base + entry->size == base) {
        return 0;
    }

    unsigned long flags = entry->flags;
    uintptr_t original_base = entry->base;
    size_t original_size = entry->size;

    size_t entries_after = map->num_entries - index;
    memmove(&map->entries[index+1], &map->entries[index], sizeof(struct mem_flags_entry)*entries_after);
    struct mem_flags_entry *bottom = &map->entries[index];
    struct mem_flags_entry *top = &map->entries[index+1];

    bottom->flags = flags;
    top->flags = flags;

    bottom->base = original_base;
    bottom->size = base - original_base;

    top->base = original_base + bottom->size;
    top->size = original_size - bottom->size;

    dprintk("Split [%p - %p) into [%p - %p) and [%p - %p)\n",
            original_base, original_base + original_size,
            bottom->base, bottom->base + bottom->size,
            top->base, top->base + top->size);

    map->num_entries++;

    return 0;
}

static int
__mem_flags_change_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long flags_input,
        unsigned long(*flag_func)(unsigned long flags, unsigned long flags_input))
{
    int res = 0;
    size_t index;

__recurse:
    if(size <= 0) {
        return 0;
    }

    res = mem_flags_get_overlapping(map, base, &index);
    if(res) {
        return res;
    }

    if(map->entries[index].base == base) {
        if(map->entries[index].size <= size) {
            // Apply our flag func, we cover the region entirely
            map->entries[index].flags = (*flag_func)(map->entries[index].flags, flags_input);

            size -= map->entries[index].size;
            base += map->entries[index].size;

            if(size > 0) {
                goto __recurse;
            } else {
                return 0;
            }

        } else {
            // We need to split the region at our end
            dprintk("Splitting Flags End\n");
            res = __mem_flags_split_at(map, map->entries[index].base + size);
            if(res) {
                return res;
            }

            goto __recurse;
        }
        
    } else {
        // We need to split the region at our base
        dprintk("Splitting Flags Base base = %p, region_base = %p\n", base, map->entries[index].base);
        res = __mem_flags_split_at(map, base);
        if(res) {
            return res;
        }

        goto __recurse;
    }
}


static int 
mem_flags_change_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long flags_input,
        unsigned long(*flag_func)(unsigned long flags, unsigned long flags_input))
{
    int res;
    res = __mem_flags_change_flags(map, base, size, flags_input, flag_func);
    return res;
}

static inline unsigned long 
__mem_flags_set_flags_func(unsigned long flags, unsigned long to_set) {
    return flags | to_set;
}

static inline unsigned long 
__mem_flags_clear_flags_func(unsigned long flags, unsigned long to_clear) {
    //printk("clear_flags 0x%x -> 0x%x\n",
    //        flags, flags & ~to_clear);
    return flags & ~to_clear;
}

int 
mem_flags_set_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long to_set)
{
    return mem_flags_change_flags(
            map,
            base,
            size,
            to_set,
            __mem_flags_set_flags_func);
}

int 
mem_flags_clear_flags(
        struct mem_flags *map,
        uintptr_t base,
        size_t size,
        unsigned long to_clear)
{
    return mem_flags_change_flags(
            map,
            base,
            size,
            to_clear,
            __mem_flags_clear_flags_func);
}

unsigned long
mem_flags_read(
        struct mem_flags *map,
        uintptr_t addr)
{
    struct mem_flags_entry *entry;
    entry = mem_flags_read_entry(map, addr);
    if(entry == NULL) {
        return 0;
    }
    return entry->flags;
}

struct mem_flags_entry *
mem_flags_read_entry(
        struct mem_flags *map,
        uintptr_t addr)
{
    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *entry = &map->entries[i];
        uintptr_t end = entry->base + entry->size;
        if(entry->base <= addr && addr < end) {
            return entry;
        }
    }
    return NULL;
}
int
mem_flags_find_and_reserve(
        struct mem_flags *map,
        size_t size,
        order_t align_order,
        unsigned long must_be_set,
        unsigned long must_be_clear,
        unsigned long to_set,
        unsigned long to_clear,
        uintptr_t *base_out)
{
    int res;
    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *entry = &map->entries[i];
        if(entry->size < size) {
            continue;
        }
        uintptr_t align_size = (1ULL<<align_order);
        uintptr_t align_mask = (1ULL<<align_order)-1;
        uintptr_t align_offset = (align_size - (entry->base & align_mask)) & align_mask;

        if(entry->size - align_offset < size) {
            continue;
        }

        // We can fit, check the flags
        uintptr_t base = entry->base + align_offset;

        if(entry->flags & must_be_clear) {
            continue;
        }

        if((entry->flags & must_be_set) != must_be_set) {
            continue;
        }

        // Can fit and we have the right flags,
        // set the flags and return this region

        res = mem_flags_set_flags(map, base, size, to_set);
        if(res) {
            return res;
        }
        res = mem_flags_clear_flags(map, base, size, to_clear);
        if(res) {
            return res;
        }

        *base_out = base;
        return 0;
    }
    return -ENOMEM;
}

void
mem_flags_print(
        struct mem_flags *map,
        printk_f *printer,
        void(*flag_printer)(printk_f *printer, unsigned long flags))
{
    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *entry = &map->entries[i];
        uintptr_t end = entry->base + entry->size;
        (*printer)("[%p - %p) size=%lx ",
                entry->base, end, (unsigned long)entry->size);
        (*flag_printer)(printer, (unsigned long)entry->flags);
        (*printer)("\n");
    }
}

/*
 * Physical Memory
 */

#define MAX_PHYS_MEM_FLAGS_ENTRIES 256
static struct mem_flags __phys_mem_flags = { 0 };
static struct mem_flags_entry __phys_mem_flags_buffer[MAX_PHYS_MEM_FLAGS_ENTRIES];

struct mem_flags *
get_phys_mem_flags(void) {
    return &__phys_mem_flags;
}

static int
phys_mem_flags_static_init(void) 
{
    __phys_mem_flags.max_entries = MAX_PHYS_MEM_FLAGS_ENTRIES;
    __phys_mem_flags.entries = (struct mem_flags_entry*)__phys_mem_flags_buffer;
    spinlock_init(&__phys_mem_flags.lock);

    int res = mem_flags_clear_all(&__phys_mem_flags,0);
    if(res) {
        return res;
    }

    // Mark our 32-bit and 16-bit physical addresses
    res = mem_flags_set_flags(
            &__phys_mem_flags,
            0,
            0x10000,
            PHYS_MEM_FLAGS_16_BIT);
    if(res) {return res;}


    res = mem_flags_set_flags(
            &__phys_mem_flags,
            0,
            0x100000000,
            PHYS_MEM_FLAGS_32_BIT);
    if(res) {return res;}

    return 0;
}

static int
phys_mem_flags_reserve_kernel(void) 
{
    int res;

    extern int __kernel_phys_start[];
    extern int __kernel_phys_end[];

    res = mem_flags_set_flags(
            get_phys_mem_flags(),
            (uintptr_t)__kernel_phys_start,
            (uintptr_t)__kernel_phys_end - (uintptr_t)__kernel_phys_start,
            PHYS_MEM_FLAGS_KERNEL);

    if(res) {
        return res;
    }

    res = mem_flags_clear_flags(
            get_phys_mem_flags(), 
            (uintptr_t)__kernel_phys_start,
            (uintptr_t)__kernel_phys_end - (uintptr_t)__kernel_phys_start,
            PHYS_MEM_FLAGS_AVAIL);

    if(res) {
        return res;
    }

    return 0;
}

static void
phys_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    if(flags & PHYS_MEM_FLAGS_AVAIL)      {(*printer)("[AVAIL]");}
    if(flags & PHYS_MEM_FLAGS_FW_RESV)    {(*printer)("[FW_RESV]");}
    if(flags & PHYS_MEM_FLAGS_KERNEL)     {(*printer)("[KERNEL]");}
    if(flags & PHYS_MEM_FLAGS_RAM)        {(*printer)("[RAM]");}
    if(flags & PHYS_MEM_FLAGS_SAVE)       {(*printer)("[SAVE]");}
    if(flags & PHYS_MEM_FLAGS_DEFECT)     {(*printer)("[DEFECT]");}
    if(flags & PHYS_MEM_FLAGS_FW_IGNORE)  {(*printer)("[FW_IGNORE]");}
    if(flags & PHYS_MEM_FLAGS_PAGE_ALLOC) {(*printer)("[PAGE_ALLOC]");}
    if(flags & PHYS_MEM_FLAGS_16_BIT) {(*printer)("[16]");}
    if(flags & PHYS_MEM_FLAGS_32_BIT) {(*printer)("[32]");}
}

int
phys_mem_flags_dump(void) 
{
    printk("=== Physical Memory Flags ===\n");
    mem_flags_print(get_phys_mem_flags(), printk, phys_mem_flags_printer);
    printk("=============================\n");
    return 0;
}

static int
free_phys_mem(void) 
{
    int res;
    struct mem_flags *map = get_phys_mem_flags();
    for(size_t i = 0; i < map->num_entries; i++) {
        struct mem_flags_entry *entry = &map->entries[i];
        if(!(entry->flags & PHYS_MEM_FLAGS_AVAIL)) {
            continue;
        }
        if(!(entry->flags & PHYS_MEM_FLAGS_RAM)) {
            continue;
        }
        
        // Free this region
        dprintk("Registering Buddy Allocator for region [%p - %p)\n",
                (void*)entry->base, (void*)(entry->base + entry->size));

        unsigned long page_alloc_flags = 0;
        if(entry->flags & PHYS_MEM_FLAGS_16_BIT) {
            page_alloc_flags |= PAGE_ALLOC_16BIT;
        }
        if(entry->flags & PHYS_MEM_FLAGS_32_BIT) {
            page_alloc_flags |= PAGE_ALLOC_32BIT;
        }

        res = register_buddy_page_allocator(entry->base, entry->size, page_alloc_flags);
        if(res) {
            eprintk("Failed to register buddy allocator for region [%p - %p) (err=%s)\n",
                    (void*)entry->base, (void*)(entry->base + entry->size), errnostr(res));
            continue;
        }

        res = mem_flags_clear_flags(
                map,
                entry->base,
                entry->size,
                PHYS_MEM_FLAGS_AVAIL);
        if(res) {
            eprintk("Failed to mark page_alloc region as unavailable in physical memory map!\n");
            return res;
        }

        res = mem_flags_set_flags(
                map,
                entry->base,
                entry->size,
                PHYS_MEM_FLAGS_PAGE_ALLOC);
        if(res) {
            eprintk("Failed to mark page_alloc region as allocatable in physical memory map!\n");
            return res;
        }

        dprintk("Registered Buddy Allocator for region [%p - %p)\n",
                (void*)entry->base, (void*)(entry->base + entry->size));
    }

    return 0;
}

declare_init_desc(static, phys_mem_flags_static_init, "Setting Up Physical Memory Map");
declare_init_desc(post_mem_flags, phys_mem_flags_reserve_kernel, "Reserving the Kernel in Physical Memory");
declare_init_desc(page_alloc, phys_mem_flags_dump, "Physical Memory Map Dump");
declare_init_desc(page_alloc, free_phys_mem, "Freeing Available Physical Memory");

/*
 * Virtual Memory
 */
#define MAX_VIRT_MEM_FLAGS_ENTRIES 256
static struct mem_flags __virt_mem_flags = { 0 };
static struct mem_flags_entry __virt_mem_flags_buffer[MAX_VIRT_MEM_FLAGS_ENTRIES];

struct mem_flags *
get_virt_mem_flags(void) {
    return &__virt_mem_flags;
}

static int
virt_mem_flags_static_init(void) 
{
    __virt_mem_flags.max_entries = MAX_VIRT_MEM_FLAGS_ENTRIES;
    __virt_mem_flags.entries = (struct mem_flags_entry*)__virt_mem_flags_buffer;
    spinlock_init(&__virt_mem_flags.lock);

    printk("Marking all of virtual memory available\n");
    int res = mem_flags_clear_all(&__virt_mem_flags,VIRT_MEM_FLAGS_NONCANON|VIRT_MEM_FLAGS_AVAIL);
    if(res) {return res;}

    return 0;
}

static int
virt_mem_flags_reserve_ident_map(void) 
{
    int res;

    res = mem_flags_clear_flags(
            get_virt_mem_flags(),
            CONFIG_VIRTUAL_BASE,
            (1ULL<<CONFIG_IDENTITY_MAP_ORDER),
            VIRT_MEM_FLAGS_AVAIL);

    if(res) {
        return res;
    }

    return 0;
}

static void
virt_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    if(flags & VIRT_MEM_FLAGS_NONCANON)  {(*printer)("[NONCANON]");}
    if(flags & VIRT_MEM_FLAGS_HIGHMEM) {(*printer)("[HIGH]");}
    if(flags & VIRT_MEM_FLAGS_AVAIL) {(*printer)("[AVAIL]");}
    if(flags & VIRT_MEM_FLAGS_HEAP)   {(*printer)("[HEAP]");}
    if(flags & VIRT_MEM_FLAGS_MMIO)   {(*printer)("[MMIO]");}
    if(flags & VIRT_MEM_FLAGS_PERCPU)   {(*printer)("[PERCPU]");}
}

int
virt_mem_flags_dump(void) 
{
    printk("=== Virtual Memory Flags ===\n");
    mem_flags_print(get_virt_mem_flags(), printk, virt_mem_flags_printer);
    printk("============================\n");
    return 0;
}
declare_init_desc(static, virt_mem_flags_static_init, "Initializing Virtual Memory Map");
declare_init_desc(mem_flags, virt_mem_flags_reserve_ident_map, "Reserving the Kernel Identity Map in Virtual Memory");
declare_init_desc(page_alloc, virt_mem_flags_dump, "Virtual Memory Map Dump");

