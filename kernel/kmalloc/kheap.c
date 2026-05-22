
#include <kanawha/printk.h>

#include <kanawha/bitmap.h>
#include <kanawha/buddy.h>
#include <kanawha/errno.h>
#include <kanawha/export.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kheap.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/mem_flags.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

struct kheap kmalloc_heap = {
    .heap_size = 0,
    .vbase = (void *)NULL,
    .mapped = 0,
    .region = NULL,
    .num_free_regions = 0,
};

static int
kmalloc_kheap_init(void)
{
    int res;

    uintptr_t vbase;
    virt_mem_flags_dump();
    res = mem_flags_find_and_reserve(get_virt_mem_flags(),
                                     (1ULL << CONFIG_HEAP_SIZE_ORDER),
                                     CONFIG_HEAP_ALIGN_ORDER,
                                     VIRT_MEM_FLAGS_AVAIL |
                                         VIRT_MEM_FLAGS_HIGHMEM,
                                     VIRT_MEM_FLAGS_NONCANON,
                                     VIRT_MEM_FLAGS_HEAP,
                                     VIRT_MEM_FLAGS_AVAIL,
                                     &vbase);
    virt_mem_flags_dump();
    if(res)
    {
        eprintk("Failed to find virtual memory region to put kernel heap!\n");
        return res;
    }

    return kheap_init(&kmalloc_heap,
                      (void *)vbase,
                      (1ULL << CONFIG_HEAP_SIZE_ORDER));
}
declare_init_desc(kmalloc, kmalloc_kheap_init, "Initializing Kernel Heap");

void *
kmalloc_specific(order_t align_order, size_t *size)
{
    return kheap_alloc_specific(&kmalloc_heap, align_order, size);
}

int
kfree_specific(void *addr, order_t align_order, size_t size)
{
    return kheap_free_specific(&kmalloc_heap, addr, align_order, size);
}
