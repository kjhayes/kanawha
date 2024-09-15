
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
#include <kanawha/bitmap.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>

static DECLARE_SPINLOCK(kmalloc_lock);

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
// One bit per byte in the kmalloc heap (Insanely wasteful)
// If this is used, make sure CONFIG_HEAP_SIZE_ORDER is as small as possible
static DECLARE_BITMAP(kmalloc_debug_bitmap, (1ULL<<CONFIG_HEAP_SIZE_ORDER));
#define KMALLOC_BITMAP_NUM_BITS (1ULL<<CONFIG_HEAP_SIZE_ORDER)
#endif

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

    int irq_flags = spin_lock_irq_save(&kmalloc_lock);
    void *alloc = kheap_alloc_specific(&kmalloc_heap, KMALLOC_ALIGN_ORDER, &req_size);
    if(alloc == NULL) {
        spin_unlock_irq_restore(&kmalloc_lock, irq_flags);
        dprintk("kmalloc call to kmalloc_specific(%d, size=0x%lx) returned NULL\n",
                KMALLOC_ALIGN_ORDER, size + bookkeeping_size);
        return alloc;
    }
#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < req_size; i++)
    {
        uintptr_t byte_offset = ((uintptr_t)alloc - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(bitmap_check(kmalloc_debug_bitmap, byte_offset)) {
            panic_printk("kheap_alloc_specific allocated the same byte twice (heap_offset=%p, vaddr=%p)!\n",
                    byte_offset, ((uintptr_t)alloc) + i);
            unsigned long *nearby = &kmalloc_debug_bitmap[byte_offset/BITS_PER_LONG];
            panic("Bitmap: 0x%lx, base=%p\n", *nearby, ((void*)nearby - (void*)kmalloc_debug_bitmap)*8);
        }
        bitmap_set(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    spin_unlock_irq_restore(&kmalloc_lock, irq_flags);

    size_t *size_ptr = (size_t*)alloc;
    *size_ptr = req_size;

    void *ret = alloc + bookkeeping_size;

    dprintk("kmalloc(0x%llx) -> [%p-%p)\n",size,ret,ret+size);

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

    int irq_flags = spin_lock_irq_save(&kmalloc_lock);
    int res = kheap_free_specific(&kmalloc_heap, (void*)size_ptr, size);
    if(res) {
        dprintk("kfree call to kfree_specific failed! (err=%s)\n", errnostr(res));
    }
#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < size; i++)
    {
        uintptr_t byte_offset = ((uintptr_t)size_ptr - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(!bitmap_check(kmalloc_debug_bitmap, byte_offset)) {
            panic("kfree double free detected (heap_offset=%p, vaddr=%p, alloc_offset=%p)!\n",
                    byte_offset, ((uintptr_t)addr) + i, i);
        }
        bitmap_clear(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    spin_unlock_irq_restore(&kmalloc_lock, irq_flags);

    dprintk("kfree(%p)\n", addr);
}

EXPORT_SYMBOL(kmalloc);
EXPORT_SYMBOL(kfree);

