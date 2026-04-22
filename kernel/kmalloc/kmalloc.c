
#include <kanawha/assert.h>
#include <kanawha/export.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/thread.h>

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
#include <kanawha/bitmap.h>
#include <kanawha/kheap.h>
extern struct kheap kmalloc_heap;
#endif

// DEFINE_LOCAL_IRQ_LOCK(kmalloc_lock);

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
// One bit per byte in the kmalloc heap (Insanely wasteful)
// If this is used, make sure CONFIG_HEAP_SIZE_ORDER is as small as possible
static DECLARE_BITMAP(kmalloc_debug_bitmap, (1ULL << CONFIG_HEAP_SIZE_ORDER));
#define KMALLOC_BITMAP_NUM_BITS (1ULL << CONFIG_HEAP_SIZE_ORDER)
#endif

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES
static DECLARE_ILIST(callsite_allocation_list);
#endif

struct kmalloc_hdr
{
    size_t total_size;
    unsigned long flags;

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES
    void *return_addr;
    ilist_node_t return_addr_node;
#endif
};

#define KMALLOC_ALIGN (1ULL << KMALLOC_ALIGN_ORDER)
#define KMALLOC_ALIGN_MASK (KMALLOC_ALIGN - 1)
#define KMALLOC_ALIGN_MAX_PADDING                                              \
    (KMALLOC_ALIGN - (sizeof(struct kmalloc_hdr) & KMALLOC_ALIGN_MASK))
#define KMALLOC_PADDING                                                        \
    ((KMALLOC_ALIGN_MAX_PADDING < (1ULL << KMALLOC_ALIGN_ORDER))               \
         ? KMALLOC_ALIGN_MAX_PADDING                                           \
         : 0)

struct kmallocation
{
    struct kmalloc_hdr hdr;
    uint8_t padding[KMALLOC_PADDING];
    uint8_t data[];
};

_Static_assert((sizeof(struct kmallocation) & KMALLOC_ALIGN_MASK) == 0,
               "sizeof(struct kmallocation) is not a multiple of "
               "1ULL<<KMALLOC_ALIGN_ORDER)");

void *
kmalloc(size_t size, unsigned long flags)
{
    if(size == 0)
    {
        // Free will ignore NULL so this is fine
        return NULL;
    }

    size_t req_size = sizeof(struct kmallocation) + size;

    // kmalloc_lock_acquire();

    void *alloc = kmalloc_specific(KMALLOC_ALIGN_ORDER, &req_size);
    if(alloc == NULL)
    {
        // kmalloc_lock_release();
        dprintk("kmalloc call to kmalloc_specific(%d, size=0x%lx) "
                "returned NULL\n",
                KMALLOC_ALIGN_ORDER,
                size + bookkeeping_size);
        return alloc;
    }

    DEBUG_ASSERT(req_size >= size + sizeof(struct kmallocation));

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < req_size; i++)
    {
        uintptr_t byte_offset = (alloc - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(bitmap_check(kmalloc_debug_bitmap, byte_offset))
        {
            do_panic_printk("kmalloc_specific allocated the same byte twice "
                            "(heap_offset=%p, vaddr=%p)!\n",
                            byte_offset,
                            ((uintptr_t)alloc) + i);
            unsigned long *nearby =
                &kmalloc_debug_bitmap[byte_offset / BITS_PER_LONG];
            panic("Bitmap: 0x%lx, base=%p\n",
                  *nearby,
                  ((void *)nearby - (void *)kmalloc_debug_bitmap) * 8);
        }
        bitmap_set(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    struct kmallocation *allocation = (struct kmallocation *)alloc;
    allocation->hdr.total_size = req_size;
    allocation->hdr.flags = flags;

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES
    allocation->hdr.return_addr = __builtin_return_address(0);
    int found = 0;
    ilist_node_t *iter;
    ilist_for_each(iter, &callsite_allocation_list)
    {
        struct kmallocation *other =
            container_of(iter, struct kmallocation, hdr.return_addr_node);
        if(other->hdr.return_addr == allocation->hdr.return_addr)
        {
            found = 1;
            ilist_insert_before(&callsite_allocation_list,
                                &allocation->hdr.return_addr_node,
                                iter);
            break;
        }
    }
    if(!found)
    {
        ilist_push_head(&callsite_allocation_list,
                        &allocation->hdr.return_addr_node);
    }
#endif

    if(flags & KM_THREAD) {
        struct thread_state *thread = current_thread();
        if(thread == NULL) {
            wprintk("allocating KM_THREAD allocation without a current thread!\n");
        } else {
            thread->kmalloc_allocated += req_size;
        }
    }

    // kmalloc_lock_release();

    void *ret = allocation->data;
    dprintk("kmalloc(0x%llx) -> [%p-%p)\n", size, ret, ret + size);
    return ret;
}

void
kfree(void *addr)
{
    if(addr == NULL)
    {
        // Free is allowed to ignore NULL pointers
        return;
    }

    // kmalloc_lock_acquire();

    struct kmallocation *allocation =
        container_of(addr, struct kmallocation, data);

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES
    ilist_remove(&callsite_allocation_list, &allocation->hdr.return_addr_node);
#endif

    size_t size = allocation->hdr.total_size;

    if(allocation->hdr.flags & KM_THREAD) {
        struct thread_state *thread = current_thread();
        if(thread == NULL) {
            wprintk("freeing KM_THREAD allocation without a current thread!\n");
        } else {
            thread->kmalloc_allocated -= allocation->hdr.total_size;
        }
    }

    int res = kfree_specific(allocation, KMALLOC_ALIGN_ORDER, size);
    if(res)
    {
        dprintk("kfree call to kfree_specific failed! (err=%s)\n",
                errnostr(res));
    }

#ifdef CONFIG_DEBUG_KMALLOC_BITMAP
    for(size_t i = 0; i < size; i++)
    {
        uintptr_t byte_offset = ((void *)allocation - kmalloc_heap.vbase) + i;
        DEBUG_ASSERT(byte_offset < KMALLOC_BITMAP_NUM_BITS);
        if(!bitmap_check(kmalloc_debug_bitmap, byte_offset))
        {
            panic("kfree double free detected (heap_offset=%p, "
                  "vaddr=%p, "
                  "alloc_offset=%p)!\n",
                  byte_offset,
                  ((uintptr_t)addr) + i,
                  i);
        }
        bitmap_clear(kmalloc_debug_bitmap, byte_offset);
    }
#endif

    // kmalloc_lock_release();

    dprintk("kfree(%p)\n", addr);
}

EXPORT_SYMBOL(kmalloc);
EXPORT_SYMBOL(kfree);

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES_LOG_AT_LAUNCH
static int
kmalloc_dump_callsite_info(void)
{
    // kmalloc_lock_acquire();

    size_t total = 0;

    void *current_callsite = NULL;
    size_t amt = 0;

#define LOG_CALLSITE()                                                         \
    do                                                                         \
    {                                                                          \
        printk("kmalloc call @ %p -> 0x%lx bytes allocated\n",                 \
               current_callsite,                                               \
               amt);                                                           \
    } while(0)

    ilist_node_t *iter;
    ilist_for_each(iter, &callsite_allocation_list)
    {
        struct kmallocation *alloc =
            container_of(iter, struct kmallocation, hdr.return_addr_node);
        if(alloc->hdr.return_addr != current_callsite)
        {
            if(amt > 0)
            {
                total += amt;
                LOG_CALLSITE();
            }
            current_callsite = alloc->hdr.return_addr;
            amt = alloc->hdr.total_size;
        }
        else
        {
            amt += alloc->hdr.total_size;
        }
    }
    if(amt > 0)
    {
        total += amt;
        LOG_CALLSITE();
    }

    printk("Kernel Heap Total Allocated: (0x%lx bytes)\n", (ul_t)total);

    // kmalloc_lock_release();
    return 0;
}
declare_init(launch, kmalloc_dump_callsite_info);
#endif

#ifdef CONFIG_KMALLOC_TRACK_CALLSITES_LOG_PERIODIC
#include <kanawha/event.h>
static void
periodic_kmalloc_dump_callsite_info_callback(void *state)
{
    int res;
    res = kmalloc_dump_callsite_info();
    if(res)
    {
        wprintk("Failed to dump kmalloc callsite info (err=%s)\n",
                errnostr(res));
    }
}
static int
init_periodic_kmalloc_dump_callsite_info(void)
{
    static struct periodic_event *evt;
    evt = create_periodic_event(
        sec_to_duration(CONFIG_KMALLOC_TRACK_CALLSITES_SEC_PERIOD),
        NULL,
        periodic_kmalloc_dump_callsite_info_callback);
    if(evt == NULL)
    {
        wprintk("Failed to start periodic event logging kmalloc callsites!\n");
    }
    return 0;
}
declare_init(launch, init_periodic_kmalloc_dump_callsite_info);
#endif
