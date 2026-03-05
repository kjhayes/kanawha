
#include <kanawha/bitmap.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/mmio.h>
#include <kanawha/vmem.h>

static void *mmio_region_base;
#define MMIO_REGION_BITMAP_NUM_ENTRIES                                         \
    (1ULL << (CONFIG_MMIO_RESERVE_SIZE_ORDER - VMEM_MIN_PAGE_ORDER))
static DECLARE_BITMAP(mmio_region_bitmap, MMIO_REGION_BITMAP_NUM_ENTRIES);
static struct vmem_region *__mmio_vmem_region;

struct vmem_region *
mmio_vmem_region(void)
{
    return __mmio_vmem_region;
}

static int
mmio_page_fault_handler(struct excp_state *state,
                        struct vmem_region_ref *ref,
                        uintptr_t offset,
                        unsigned long pf_flags,
                        void *priv_state)
{
    eprintk("MMIO Region Page Fault! (offset=0x%llx)\n", (ull_t)offset);
    return PAGE_FAULT_UNHANDLED;
}

static int
mmio_create_mmio_map(void)
{
    int res;

    __mmio_vmem_region =
        vmem_region_create_paged(1ULL << CONFIG_MMIO_RESERVE_SIZE_ORDER,
                                 mmio_page_fault_handler,
                                 NULL);
    if(__mmio_vmem_region == NULL)
    {
        return -ENOMEM;
    }

    size_t size = (1ULL << CONFIG_MMIO_RESERVE_SIZE_ORDER);
    res = mem_flags_find_and_reserve(get_virt_mem_flags(),
                                     size,
                                     vmem_region_alignment(__mmio_vmem_region),
                                     VIRT_MEM_FLAGS_HIGHMEM |
                                         VIRT_MEM_FLAGS_AVAIL,
                                     VIRT_MEM_FLAGS_NONCANON,
                                     VIRT_MEM_FLAGS_MMIO,
                                     VIRT_MEM_FLAGS_AVAIL,
                                     (uintptr_t *)&mmio_region_base);

    if(res)
    {
        vmem_region_destroy(__mmio_vmem_region);
        return res;
    }

    printk("Reserved MMIO Virtual Memory Region [%p - %p)\n",
           mmio_region_base,
           mmio_region_base + size);

    res = vmem_force_mapping(__mmio_vmem_region, mmio_region_base);
    if(res)
    {
        vmem_region_destroy(__mmio_vmem_region);
        return res;
    }

    return 0;
}
declare_init_desc(post_vmem,
                  mmio_create_mmio_map,
                  "Creating MMIO Virtual Memory Region");

void __mmio *
mmio_map(void __phys *paddr, size_t size)
{
    int res;

    struct mem_flags *flags = get_phys_mem_flags();
    res = mem_flags_check_region(flags,
                                 (uintptr_t)paddr,
                                 size,
                                 0,
                                 PHYS_MEM_FLAGS_MMIO);
    if(res)
    {
        eprintk("mmio_map: Failed because physical region is already mapped! "
                "(paddr=%p, size=%p)\n",
                (uintptr_t)paddr,
                (uintptr_t)size);
        return NULL;
    }

    res =
        mem_flags_set_flags(flags, (uintptr_t)paddr, size, PHYS_MEM_FLAGS_MMIO);
    if(res)
    {
        eprintk("mmio_map: Failed to mark physical region as MMIO! (paddr=%p, "
                "size=%p)\n",
                (uintptr_t)paddr,
                (uintptr_t)size);
        return NULL;
    }

    size_t pad_below = (uintptr_t)paddr & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1);
    size_t pad_above = (1ULL << VMEM_MIN_PAGE_ORDER) -
                       ((size + pad_below) % (1ULL << VMEM_MIN_PAGE_ORDER));
    if(pad_above == (1ULL << VMEM_MIN_PAGE_ORDER))
    {
        pad_above = 0;
    }
    size_t total_size = size + pad_below + pad_above;

    dprintk("pad_below = %p, pad_above = %p, total_size = %p\n",
            pad_below,
            pad_above,
            total_size);

    DEBUG_ASSERT_MSG((total_size & ((1ULL << VMEM_MIN_PAGE_ORDER) - 1)) == 0,
                     "Padding math is flawed in mmio_map!");

    size_t num_pages = total_size >> VMEM_MIN_PAGE_ORDER;
    void __phys *page_base =
        (void __phys *)((uintptr_t)paddr &
                        ~((1ULL << VMEM_MIN_PAGE_ORDER) - 1));

    size_t page_bit = bitmap_find_clear_range(mmio_region_bitmap,
                                              MMIO_REGION_BITMAP_NUM_ENTRIES,
                                              num_pages);
    if(page_bit == MMIO_REGION_BITMAP_NUM_ENTRIES)
    {
        eprintk("mmio_map: not enough space in MMIO virtual memory region!\n");
        return NULL;
    }
    dprintk("bitmap_find_clear_range(num_bits=0x%lx) -> bit=0x%lx\n",
            num_pages,
            page_bit);

    size_t region_offset = (page_bit << VMEM_MIN_PAGE_ORDER);

    for(size_t i = 0; i < num_pages; i++)
    {
        DEBUG_ASSERT(bitmap_check(mmio_region_bitmap, page_bit + i) == 0);
        bitmap_set(mmio_region_bitmap, page_bit + i);
    }

    res = vmem_paged_region_map(__mmio_vmem_region,
                                region_offset,
                                page_base,
                                total_size,
                                VMEM_REGION_WRITE | VMEM_REGION_READ |
                                    VMEM_REGION_NOCACHE);

    if(res)
    {
        // Free the region in the bitmap
        for(size_t i = 0; i < num_pages; i++)
        {
            bitmap_clear(mmio_region_bitmap, page_bit + i);
        }
        eprintk("mmio_map: vmem failed to map region!\n");
        return NULL;
    }

    void *addr = (void *)(mmio_region_base + region_offset);

    dprintk("mmio_map(%p, 0x%lx) -> %p\n", page_base, total_size, addr);

    return (void __mmio *)addr + pad_below;
}

int
mmio_unmap(void __mmio *addr, size_t size)
{
    return -EUNIMPL;
}
