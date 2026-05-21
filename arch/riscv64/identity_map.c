
#include <arch/riscv64/csr.h>
#include <arch/riscv64/mmu.h>
#include <arch/riscv64/vmem.h>
#include <kanawha/init.h>
#include <kanawha/pointer.h>
#include <kanawha/section.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>
#include <kanawha/mem_flags.h>

#ifdef CONFIG_RISCV64_SV57
#define ROOT_PAGE_LEVEL 4
#define ROOT_PAGE_SIZE RISCV64_SV_PAGE_SIZE_LEVEL_4
#define ROOT_PAGE_ORDER RISCV64_SV_PAGE_ORDER_LEVEL_4
#define SATP_MODE (10ULL << 60)
#define VIRTUAL_BASE_ROOT_INDEX                                                \
    RISCV64_SV_LEVEL_4_INDEX_OF_ADDR(CONFIG_RISCV64_KERNEL_VIRTUAL_BASE)
#else
#ifdef CONFIG_RISCV64_SV48
#define ROOT_PAGE_LEVEL 3
#define ROOT_PAGE_SIZE RISCV64_SV_PAGE_SIZE_LEVEL_3
#define ROOT_PAGE_ORDER RISCV64_SV_PAGE_ORDER_LEVEL_3
#define SATP_MODE (9ULL << 60)
#define VIRTUAL_BASE_ROOT_INDEX                                                \
    RISCV64_SV_LEVEL_3_INDEX_OF_ADDR(CONFIG_RISCV64_KERNEL_VIRTUAL_BASE)
#else
#ifdef CONFIG_RISCV64_SV39
#define ROOT_PAGE_LEVEL 2
#define ROOT_PAGE_SIZE RISCV64_SV_PAGE_SIZE_LEVEL_2
#define ROOT_PAGE_ORDER RISCV64_SV_PAGE_ORDER_LEVEL_2
#define SATP_MODE (8ULL << 60)
#define VIRTUAL_BASE_ROOT_INDEX                                                \
    RISCV64_SV_LEVEL_2_INDEX_OF_ADDR(CONFIG_RISCV64_KERNEL_VIRTUAL_BASE)
#endif
#endif
#endif

#if ((CONFIG_RISCV64_KERNEL_VIRTUAL_BASE % ROOT_PAGE_SIZE) != 0)
#error                                                                         \
    "Could not map kernel to provided virtual base! (it is not a multiple of the root page table page size!"
#endif

// Nothing we can do this early at boot, just loop forever :(
#define PANIC(msg)                                                             \
    do                                                                         \
    {                                                                          \
        while(1)                                                               \
        {                                                                      \
        }                                                                      \
    } while(0);

#define RISCV64_BOOT_PAGE_TABLE_CACHE_SIZE                                     \
    (1                 /* Atleast 1 for the root page table */                 \
     + ROOT_PAGE_LEVEL /* Allow at least a single tree from root to level 0    \
                        */                                                     \
     + (1ULL                                                                   \
        << (CONFIG_RISCV64_BOOT_KERNEL_MAP_ORDER >= 21                         \
                ? CONFIG_RISCV64_BOOT_KERNEL_MAP_ORDER - 21                    \
                : 0)) /* To allow the kernel to be mapped at 2MB addresses*/   \
    )

__boot_data static struct riscv64_sv_page_table
    riscv64_boot_page_table_cache[RISCV64_BOOT_PAGE_TABLE_CACHE_SIZE];
__boot_data static size_t riscv64_boot_page_table_cache_allocated_count = 0;

static inline struct riscv64_sv_page_table *__boot_text
riscv64_boot_alloc_page_table(void)
{
    if(riscv64_boot_page_table_cache_allocated_count >=
       RISCV64_BOOT_PAGE_TABLE_CACHE_SIZE)
    {
        PANIC("Failed to allocate boot page table!\n");
    }
    struct riscv64_sv_page_table *table =
        &riscv64_boot_page_table_cache
            [riscv64_boot_page_table_cache_allocated_count];
    riscv64_boot_page_table_cache_allocated_count++;
    return table;
}

extern uint8_t __kernel_virt_start[];
extern uint8_t __kernel_virt_end[];
__boot_data static void __phys *volatile kernel_start =
    (void __phys *)&__kernel_virt_start;
__boot_data static void __phys *volatile kernel_end =
    (void __phys *)&__kernel_virt_end;

static void __boot_text
riscv64_boot_drill_mapping(struct riscv64_sv_page_table *pt,
                           int pt_level,
                           void __phys *mapping_to,
                           void *mapping_from,
                           size_t *mapping_size,
                           int may_overmap)
{
    size_t pt_page_size;
    order_t pt_page_order;
    size_t pt_index;

    if((((uintptr_t)mapping_to) &
        ((1ULL << RISCV64_SV_PAGE_ORDER_LEVEL_0) - 1)) != 0)
    {
        PANIC("Cannot drill mapping to a physical region which is not "
              "aligned "
              "to the minimum page size!");
    }
    if((((uintptr_t)mapping_from) &
        ((1ULL << RISCV64_SV_PAGE_ORDER_LEVEL_0) - 1)) != 0)
    {
        PANIC("Cannot drill mapping from a virtual region which is not "
              "aligned "
              "to the minimum page size!");
    }
    if(!may_overmap && ((((uintptr_t)*mapping_size) &
                         ((1ULL << RISCV64_SV_PAGE_ORDER_LEVEL_0) - 1)) != 0))
    {
        PANIC("Cannot drill mapping of size which is not a multiple of the "
              "minimum page size if overmapping is disabled!");
    }

    // NOTE: Do not make this if-else chain into a switch statement,
    //       if so, clang tends to generate a jump table which will be placed
    //       in the regular .text/data sections instead of in the .boot.text or
    //       .boot.data sections
    if(pt_level == 0)
    {
        pt_page_size = RISCV64_SV_PAGE_SIZE_LEVEL_0;
        pt_page_order = RISCV64_SV_PAGE_ORDER_LEVEL_0;
        pt_index = RISCV64_SV_LEVEL_0_INDEX_OF_ADDR((uintptr_t)mapping_from);
    }
    else if(pt_level == 1)
    {
        pt_page_size = RISCV64_SV_PAGE_SIZE_LEVEL_1;
        pt_page_order = RISCV64_SV_PAGE_ORDER_LEVEL_1;
        pt_index = RISCV64_SV_LEVEL_1_INDEX_OF_ADDR((uintptr_t)mapping_from);
    }
    else if(pt_level == 2)
    {
        pt_page_size = RISCV64_SV_PAGE_SIZE_LEVEL_2;
        pt_page_order = RISCV64_SV_PAGE_ORDER_LEVEL_2;
        pt_index = RISCV64_SV_LEVEL_2_INDEX_OF_ADDR((uintptr_t)mapping_from);
    }
    else if(pt_level == 3)
    {
        pt_page_size = RISCV64_SV_PAGE_SIZE_LEVEL_3;
        pt_page_order = RISCV64_SV_PAGE_ORDER_LEVEL_3;
        pt_index = RISCV64_SV_LEVEL_3_INDEX_OF_ADDR((uintptr_t)mapping_from);
    }
    else if(pt_level == 4)
    {
        pt_page_size = RISCV64_SV_PAGE_SIZE_LEVEL_4;
        pt_page_order = RISCV64_SV_PAGE_ORDER_LEVEL_4;
        pt_index = RISCV64_SV_LEVEL_4_INDEX_OF_ADDR((uintptr_t)mapping_from);
    }
    else
    {
        PANIC("Invalid page table level during boot page table drilling");
    }

    if(pt_index > RISCV64_SV_ENTRIES_PER_LEVEL)
    {
        PANIC("Invalid page table index during boot page table drilling");
    }
    uint64_t *entry = &pt->entries[pt_index];

    int virt_aligned =
        (((uintptr_t)mapping_from & ((1ULL << pt_page_order) - 1)) == 0);
    int phys_aligned =
        (((uintptr_t)mapping_to & ((1ULL << pt_page_order) - 1)) == 0);
    int entry_covers = (pt_page_size >= *mapping_size);

    if(virt_aligned && phys_aligned &&
       ((pt_page_size >= *mapping_size) || may_overmap) &&
       !(*entry & RISCV64_SV_VALID))
    {
        // Map this entry as a leaf
        *entry = (((uintptr_t)mapping_to) >> 2) | RISCV64_SV_VALID |
                 RISCV64_SV_READ | RISCV64_SV_WRITE | RISCV64_SV_EXEC;
        if(pt_page_size >= *mapping_size)
        {
            *mapping_size = 0;
            return;
        }
        *mapping_size -= pt_page_size;
        mapping_from += pt_page_size;
        mapping_to += pt_page_size;
        if(pt_index == RISCV64_SV_ENTRIES_PER_LEVEL - 1)
        {
            // Don't recurse on this page table if we would fail
            return;
        }
        else
        {
            // Tail recurse
            return riscv64_boot_drill_mapping(pt,
                                              pt_level,
                                              mapping_to,
                                              mapping_from,
                                              mapping_size,
                                              may_overmap);
        }
    }

    // If this is mapped as a leaf page there is nothing we can do
    if((*entry & RISCV64_SV_VALID) &&
       (*entry & (RISCV64_SV_READ | RISCV64_SV_EXEC)))
    {
        PANIC("Overlapping regions when drilling boot page tables");
    }

    // If this is not mapped as a table, force it to be mapped to a table

    struct riscv64_sv_page_table *subtable;
    if((*entry & RISCV64_SV_VALID) == 0)
    {
        subtable = riscv64_boot_alloc_page_table();
        *entry = (((uintptr_t)subtable) >> 2) | RISCV64_SV_VALID;
    }
    else
    {
        subtable = (void *)(uintptr_t)(((*entry) << 2) &
                                       ~((1ULL << RISCV64_SV_TABLE_ALIGN) - 1));
    }

    riscv64_boot_drill_mapping(subtable,
                               pt_level - 1,
                               mapping_to,
                               mapping_from,
                               mapping_size,
                               may_overmap);
    if(*mapping_size == 0 || (pt_index == (RISCV64_SV_ENTRIES_PER_LEVEL - 1)))
    {
        // Do not recurse (either we are done entirely, or done with this
        // level
        return;
    }

    mapping_to += pt_page_size;
    mapping_from += pt_page_size;
    // Tail recurse
    return riscv64_boot_drill_mapping(pt,
                                      pt_level,
                                      mapping_to,
                                      mapping_from,
                                      mapping_size,
                                      may_overmap);
}

void *__boot_text
riscv64_boot_setup_paging(void __phys *kernel_phys_base)
{
    { // Clear every page in the page table cache
        uint64_t *cache = (uint64_t *)riscv64_boot_page_table_cache;
        for(size_t i = 0; i < RISCV64_SV_ENTRIES_PER_LEVEL *
                                  RISCV64_BOOT_PAGE_TABLE_CACHE_SIZE;
            i++)
        {
            cache[i] = 0;
        }
    }

    struct riscv64_sv_page_table *root_pt = riscv64_boot_alloc_page_table();

    // Low mem Identity Map
    size_t mapping_size = 1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER;
    riscv64_boot_drill_mapping(root_pt,
                               ROOT_PAGE_LEVEL,
                               (void __phys *)0x0,
                               (void *)0x0,
                               &mapping_size,
                               1);

    if(mapping_size > 0)
    {
        PANIC("Failed to map entire low-mem identity map!");
    }

    // High-mem Kernel
    mapping_size = kernel_end - kernel_start;
    riscv64_boot_drill_mapping(root_pt,
                               ROOT_PAGE_LEVEL,
                               (void __phys *)kernel_phys_base,
                               (void *)CONFIG_RISCV64_KERNEL_VIRTUAL_BASE,
                               &mapping_size,
                               1);

    if(mapping_size > 0)
    {
        PANIC("Failed to map kernel into high-mem!");
    }

    // High-mem identity map
    uintptr_t highmem_identity_map_base =
        (((uintptr_t)kernel_end + ((1ULL << ROOT_PAGE_ORDER) - 1)) &
         ~((1ULL << ROOT_PAGE_ORDER) - 1));
    mapping_size = (1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER);
    riscv64_boot_drill_mapping(root_pt,
                               ROOT_PAGE_LEVEL,
                               (void __phys *)0x0,
                               (void *)highmem_identity_map_base,
                               &mapping_size,
                               1);
    if(mapping_size > 0)
    {
        PANIC("Failed to map high-mem identity map!");
    }

    // Enable Paging
    uint64_t satp_value = SATP_MODE | (((uint64_t)root_pt) >> 12);

    write_csr(satp, satp_value);

    // Now that we have paging, we can access the the standard text and data
    // sections in highmem (must use indirection carefully though due to
    // relocations)

    return (void *)highmem_identity_map_base;
}

static struct vmem_region *identity_map_region = NULL;

static int
riscv64_map_identity_map_region(void)
{
    int res;

    size_t phys_mem_mapping_size = (1ULL << CONFIG_RISCV64_IDENTITY_MAP_ORDER);
    identity_map_region = vmem_region_create_direct(
        0x0,
        phys_mem_mapping_size,
        VMEM_REGION_EXEC | VMEM_REGION_WRITE | VMEM_REGION_READ);

    if(identity_map_region == NULL)
    {
        eprintk("OOM Error when initializing kernel identity map "
                "vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(identity_map_region,
                             (void *)__riscv64_identity_map_offset);
    if(res)
    {
        eprintk("Failed to map identity map vmem_region into default "
                "vmem_map! "
                "(err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(vmem,
                  riscv64_map_identity_map_region,
                  "Creating Identity Map Virtual Memory Region");

static struct vmem_region *kernel_map_region = NULL;

static int
riscv64_map_kernel_region(void)
{
    int res;

    size_t map_size = (arch_kernel_phys_size() + 0xFFF) & ~0xFFF;
    kernel_map_region = vmem_region_create_direct(
        arch_kernel_phys_start(),
        map_size,
        VMEM_REGION_EXEC | VMEM_REGION_WRITE | VMEM_REGION_READ);

    if(kernel_map_region == NULL)
    {
        eprintk("OOM Error when initializing default kernel vmem_region!\n");
        return -ENOMEM;
    }

    res = vmem_force_mapping(kernel_map_region,
                             (void *)CONFIG_RISCV64_KERNEL_VIRTUAL_BASE);
    if(res)
    {
        eprintk("Failed to map kernel vmem_region into default vmem_map! "
                "(err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}

declare_init_desc(vmem,
                  riscv64_map_kernel_region,
                  "Creating Kernel Virtual Memory Region");

