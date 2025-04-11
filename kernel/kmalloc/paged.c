/*
 * THIS IS A TERRIBLE (AND LEAKY) ALLOCATOR
 *
 * But it allows every heap allocation to have an unmapped page placed directly after it.
 * And so any heap buffer overflows should trigger a page fault which can be debugged,
 * instead of silently corrupting some other data on the heap.
 */

#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/buddy.h>
#include <kanawha/mem_flags.h>
#include <kanawha/errno.h>
#include <kanawha/init.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/export.h>
#include <kanawha/kheap.h>
#include <kanawha/bitmap.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>

static DECLARE_SPINLOCK(kmalloc_paged_lock);
static struct vmem_region *kmalloc_paged_vmem_region = NULL;
static void *kmalloc_paged_region_base = NULL;

_Static_assert(VMEM_MIN_PAGE_ORDER < CONFIG_HEAP_SIZE_ORDER, "VMEM_MIN_PAGE_ORDER must be less than CONFIG_HEAP_SIZE_ORDER");

#define KMALLOC_PAGED_NUM_PAGES (1ULL<<(CONFIG_HEAP_SIZE_ORDER-VMEM_MIN_PAGE_ORDER))
static DECLARE_BITMAP(kmalloc_page_bitmap, KMALLOC_PAGED_NUM_PAGES);

static int
kmalloc_paged_page_fault_handler(
        struct vmem_region_ref *region,
        uintptr_t offset,
        unsigned long flags,
        void *priv_state
        )
{
    eprintk("kmalloc: something tried to touch heap guard page!\n");
    return PAGE_FAULT_UNHANDLED;
}

static int
kmalloc_paged_init(void)
{
    int res;

    uintptr_t vbase;
    res = mem_flags_find_and_reserve(
            get_virt_mem_flags(),
            (1ULL<<CONFIG_HEAP_SIZE_ORDER),
            CONFIG_HEAP_ALIGN_ORDER,
            VIRT_MEM_FLAGS_AVAIL|VIRT_MEM_FLAGS_HIGHMEM,
            VIRT_MEM_FLAGS_NONCANON,
            VIRT_MEM_FLAGS_HEAP,
            VIRT_MEM_FLAGS_AVAIL,
            &vbase);
    if(res) {
        eprintk("Failed to find virtual memory region to put kernel heap!\n");
        return res;
    }

    kmalloc_paged_region_base = (void*)vbase;

    kmalloc_paged_vmem_region =
        vmem_region_create_paged(
                1ULL<<CONFIG_HEAP_SIZE_ORDER,
                kmalloc_paged_page_fault_handler,
                NULL);
    if(kmalloc_paged_vmem_region == NULL) {
        return -ENOMEM;
    }

    res = vmem_force_mapping(
                kmalloc_paged_vmem_region,
                kmalloc_paged_region_base
                );
    if(res) {
        vmem_region_destroy(kmalloc_paged_vmem_region);
        kmalloc_paged_vmem_region = NULL;
        return res;
    }

    for(size_t i = 0; i < KMALLOC_PAGED_NUM_PAGES; i++) {
        bitmap_clear(kmalloc_page_bitmap, i);
    }

    return 0;
}
declare_init_desc(kmalloc, kmalloc_paged_init, "Initializing Kernel Heap");

void * kmalloc(size_t size)
{
    int res;
    int irq_flags = spin_lock_irq_save(&kmalloc_paged_lock);

    // Round up to nearest multiple of 16 bytes
    size += (1ULL<<4)-1;
    size &= ~((1ULL<<4)-1);

    // Determine the number of pages needed for the allocation
    size_t pages_needed = ((size + ((1ULL<<VMEM_MIN_PAGE_ORDER)-1ULL)) & ~((1ULL<<VMEM_MIN_PAGE_ORDER)-1ULL)) >> VMEM_MIN_PAGE_ORDER;

    // Guard page at the end
    pages_needed++;

    size_t pageno = bitmap_find_clear_range(
            kmalloc_page_bitmap,
            KMALLOC_PAGED_NUM_PAGES,
            pages_needed);
    if(pageno >= KMALLOC_PAGED_NUM_PAGES) {
        // Out of Memory
        spin_unlock_irq_restore(&kmalloc_paged_lock, irq_flags);
        eprintk("Failed to find free region in kmalloc bitmap!\n");
        return NULL;
    }

    size_t offset = (pageno * (1ULL<<VMEM_MIN_PAGE_ORDER));

    // Map the pages

    bitmap_set(kmalloc_page_bitmap, pageno + (pages_needed-1));

    for(size_t i = 0; i < pages_needed-1; i++)
    {
        bitmap_set(kmalloc_page_bitmap, pageno + i);

        void __phys *page;
        res = page_alloc(
                VMEM_MIN_PAGE_ORDER,
                &page,
                0);
        if(res) {
            spin_unlock_irq_restore(&kmalloc_paged_lock, irq_flags);
            eprintk("Failed to allocate backing memory for kmalloc!\n");
            return NULL;
        }

        res = vmem_paged_region_map(
                kmalloc_paged_vmem_region,
                offset + (i * (1ULL<<VMEM_MIN_PAGE_ORDER)),
                page,
                1ULL<<VMEM_MIN_PAGE_ORDER,
                VMEM_REGION_READ|VMEM_REGION_WRITE|VMEM_REGION_EXEC);
        if(res) {
            spin_unlock_irq_restore(&kmalloc_paged_lock, irq_flags);
            eprintk("Failed to map kmalloc backing page!\n");
            return NULL;
        }
    }

    void *page_base = kmalloc_paged_region_base + offset;
    void *page_end = page_base + ((pages_needed-1) * (1ULL<<VMEM_MIN_PAGE_ORDER));

    spin_unlock_irq_restore(&kmalloc_paged_lock, irq_flags);
    return page_end - size;
}

void kfree(void *ptr)
{
    int res;
    // We leak memory under this system (Trying to detect memory overruns at boot)
    return;
}

