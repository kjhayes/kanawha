
//#define DEBUG
#include <kanawha/printk.h>

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

static struct kheap kmalloc_heap = {
    .heap_size = 0,
    .vbase = (vaddr_t)NULL,
    .mapped = 0,
    .region = NULL,
    .num_free_regions = 0,
};

static int
kmalloc_init(void)
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

    virt_mem_flags_dump();

    return kheap_init(&kmalloc_heap, vbase, (1ULL<<CONFIG_HEAP_SIZE_ORDER));
}
declare_init_desc(kmalloc, kmalloc_init, "Initializing Kernel Heap");


void * kmalloc(size_t size)
{

    if(size == 0) {
        // Free will ignore NULL so this is fine
        return NULL;
    }
    size_t bookkeeping_size = sizeof(size_t);
    size_t bookkeeping_misalign_patch =
        (1ULL<<KMALLOC_ALIGN_ORDER)-
        (bookkeeping_size & ((1ULL<<KMALLOC_ALIGN_ORDER)-1));
    if(bookkeeping_misalign_patch == KMALLOC_ALIGN_ORDER) {
        bookkeeping_misalign_patch = 0;
    }
    bookkeeping_size += bookkeeping_misalign_patch;

    size_t req_size = size + bookkeeping_size;

    void *alloc = kheap_alloc_specific(&kmalloc_heap, KMALLOC_ALIGN_ORDER, &req_size);
    if(alloc == NULL) {
        dprintk("kmalloc call to kmalloc_specific(%d, size=0x%lx)\n",
                KMALLOC_ALIGN_ORDER, size + bookkeeping_size);
        return alloc;
    }

    size_t *size_ptr = (size_t*)alloc;
    *size_ptr = req_size;

    void *ret = alloc + bookkeeping_size;

    return ret;
}

void kfree(void *addr)
{
    if(addr == NULL) {
        // Free is allowed to ignore NULL pointers
        return;
    }
    size_t *size_ptr = (size_t*)(addr - (1ULL<<KMALLOC_ALIGN_ORDER));
    size_t size = *size_ptr;

    int res = kheap_free_specific(&kmalloc_heap, (void*)size_ptr, size);
    if(res) {
        dprintk("kfree call to kfree_specific failed! (err=%s)\n", errnostr(res));
    }
}

EXPORT_SYMBOL(kmalloc);
EXPORT_SYMBOL(kfree);

