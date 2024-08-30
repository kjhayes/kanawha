
#include <kanawha/mmio.h>
#include <kanawha/errno.h>
#include <kanawha/mem_flags.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/bitmap.h>

static vaddr_t mmio_region_base;
#define MMIO_REGION_BITMAP_NUM_ENTRIES (1ULL<<(CONFIG_MMIO_RESERVE_SIZE_ORDER - VMEM_MIN_PAGE_ORDER)) 
static DECLARE_BITMAP(mmio_region_bitmap, MMIO_REGION_BITMAP_NUM_ENTRIES);
static struct vmem_region *__mmio_vmem_region;

struct vmem_region *
mmio_vmem_region(void) {
    return __mmio_vmem_region;
}

static int
mmio_reserve_virt_mem_region(void)
{
    size_t size = (1ULL<<CONFIG_MMIO_RESERVE_SIZE_ORDER);
    int res = mem_flags_find_and_reserve(
            get_virt_mem_flags(),
            size,
            PAGE_SIZE_4KB,
            VIRT_MEM_FLAGS_HIGHMEM|VIRT_MEM_FLAGS_AVAIL,
            VIRT_MEM_FLAGS_NONCANON,
            VIRT_MEM_FLAGS_MMIO,
            VIRT_MEM_FLAGS_AVAIL,
            &mmio_region_base);

    if(res) {
        return res;
    }

    printk("Reserved MMIO Virtual Memory Region [%p - %p)\n",
            mmio_region_base, mmio_region_base + size);

    return 0;
}
declare_init_desc(post_mem_flags, mmio_reserve_virt_mem_region, "Reserving MMIO Memory Region");

static int
mmio_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long pf_flags,
        void *priv_state)
{
    eprintk("MMIO Region Page Fault! (offset=0x%llx)\n",
            (ull_t)offset);
    return PAGE_FAULT_UNHANDLED;
}

static int
mmio_create_mmio_map(void)
{
    __mmio_vmem_region =
        vmem_region_create_paged(
            1ULL<<CONFIG_MMIO_RESERVE_SIZE_ORDER,
            mmio_page_fault_handler,
            NULL);
    if(__mmio_vmem_region == NULL) {
        return -ENOMEM;
    }

    int res = vmem_force_mapping(__mmio_vmem_region, mmio_region_base);
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(post_vmem, mmio_create_mmio_map, "Creating MMIO Virtual Memory Region");

void __mmio *
mmio_map(paddr_t paddr, size_t size)
{
    int res;

    size_t pad_below = paddr & ((1ULL<<VMEM_MIN_PAGE_ORDER)-1);
    size_t pad_above = (1ULL<<VMEM_MIN_PAGE_ORDER) - (size + pad_below);
    size_t total_size = size + pad_below + pad_above;

    // TODO (Remove this check)
    if((total_size & ((1ULL<<VMEM_MIN_PAGE_ORDER)-1)) != 0) {
        panic("Padding math is flawed in mmio_map!\n");
    }

    size_t num_pages = total_size >> VMEM_MIN_PAGE_ORDER;
    paddr_t page_base = paddr & ~((1ULL<<VMEM_MIN_PAGE_ORDER)-1);

    size_t page_bit = bitmap_find_clear_range(mmio_region_bitmap, MMIO_REGION_BITMAP_NUM_ENTRIES, num_pages);
    if(page_bit == MMIO_REGION_BITMAP_NUM_ENTRIES) {
        return NULL;
    }

    size_t region_offset = (page_bit << VMEM_MIN_PAGE_ORDER);

    for(size_t i = 0; i < num_pages; i++) {
        bitmap_set(mmio_region_bitmap, page_bit + i);
    }

    res = vmem_paged_region_map(
            __mmio_vmem_region,
            region_offset,
            page_base,
            total_size,
            VMEM_REGION_WRITE|VMEM_REGION_READ|VMEM_REGION_NOCACHE);

    if(res) { 
        // Free the region in the bitmap
        for(size_t i = 0; i < num_pages; i++) {
            bitmap_clear(mmio_region_bitmap, page_bit + i);
        }       
        return NULL;
    }

    void * addr = (void*)(mmio_region_base + region_offset);

    printk("mmio_map(%p, 0x%lx) -> %p)\n",
            paddr, size, addr);

    return (void __mmio *)addr;
}

int
mmio_unmap(void __mmio * addr, size_t size)
{
    return -EUNIMPL;
}

