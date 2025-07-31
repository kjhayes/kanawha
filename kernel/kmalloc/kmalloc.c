
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/lock.h>
#include <kanawha/export.h>

DEFINE_LOCAL_IRQ_LOCK(kmalloc_lock);

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
// One bit per byte in the kmalloc heap (Insanely wasteful)
// If this is used, make sure CONFIG_HEAP_SIZE_ORDER is as small as possible
static DECLARE_BITMAP(kmalloc_debug_bitmap, (1ULL<<CONFIG_HEAP_SIZE_ORDER));
#define KMALLOC_BITMAP_NUM_BITS (1ULL<<CONFIG_HEAP_SIZE_ORDER)
#endif

struct __packed kmalloc_hdr {
    size_t total_size;
};

#define KMALLOC_ALIGN (1ULL<<KMALLOC_ALIGN_ORDER)
#define KMALLOC_ALIGN_MASK (KMALLOC_ALIGN-1)
#define KMALLOC_ALIGN_MAX_PADDING \
    (KMALLOC_ALIGN-(sizeof(struct kmalloc_hdr) & KMALLOC_ALIGN_MASK))
#define KMALLOC_PADDING \
    ((KMALLOC_ALIGN_MAX_PADDING < (1ULL<<KMALLOC_ALIGN_ORDER)) ? KMALLOC_ALIGN_MAX_PADDING : 0)

struct kmallocation {
    struct kmalloc_hdr hdr;
    uint8_t padding[KMALLOC_PADDING];
    uint8_t data[];
};

_Static_assert((sizeof(struct kmallocation) & KMALLOC_ALIGN_MASK) == 0, "sizeof(struct kmallocation) is not a multiple of 1ULL<<KMALLOC_ALIGN_ORDER)");

void * kmalloc(size_t size, unsigned long flags)
{
    if(size == 0) {
        // Free will ignore NULL so this is fine
        return NULL;
    }

    size_t req_size = sizeof(struct kmallocation) + size;

    kmalloc_lock_acquire();

    void *alloc = kmalloc_specific(KMALLOC_ALIGN_ORDER, &req_size);
    if(alloc == NULL) {
        kmalloc_lock_release();
        dprintk("kmalloc call to kmalloc_specific(%d, size=0x%lx) returned NULL\n",
                KMALLOC_ALIGN_ORDER, size + bookkeeping_size);
        return alloc;
    }

    DEBUG_ASSERT(req_size >= size + sizeof(struct kmallocation));

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < req_size; i++)
    {
        uintptr_t byte_offset = (alloc - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(bitmap_check(kmalloc_debug_bitmap, byte_offset)) {
            do_panic_printk("kmalloc_specific allocated the same byte twice (heap_offset=%p, vaddr=%p)!\n",
                    byte_offset, ((uintptr_t)alloc) + i);
            unsigned long *nearby = &kmalloc_debug_bitmap[byte_offset/BITS_PER_LONG];
            panic("Bitmap: 0x%lx, base=%p\n", *nearby, ((void*)nearby - (void*)kmalloc_debug_bitmap)*8);
        }
        bitmap_set(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    kmalloc_lock_release();

    struct kmallocation *allocation = (struct kmallocation *)alloc;
    allocation->hdr.total_size = req_size;

    void *ret = allocation->data;

    dprintk("kmalloc(0x%llx) -> [%p-%p)\n",size,ret,ret+size);

    return ret;
}

void kfree(void *addr)
{
    if(addr == NULL) {
        // Free is allowed to ignore NULL pointers
        return;
    }

    kmalloc_lock_acquire();

    struct kmallocation *allocation = container_of(addr, struct kmallocation, data);

    size_t size = allocation->hdr.total_size;

    int res = kfree_specific(allocation, size);
    if(res) {
        dprintk("kfree call to kfree_specific failed! (err=%s)\n", errnostr(res));
    }

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < size; i++)
    {
        uintptr_t byte_offset = ((void *)allocation - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(!bitmap_check(kmalloc_debug_bitmap, byte_offset)) {
            panic("kfree double free detected (heap_offset=%p, vaddr=%p, alloc_offset=%p)!\n",
                    byte_offset, ((uintptr_t)addr) + i, i);
        }
        bitmap_clear(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    kmalloc_lock_release();

    dprintk("kfree(%p)\n", addr);
}

EXPORT_SYMBOL(kmalloc);
EXPORT_SYMBOL(kfree);

