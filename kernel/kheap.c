
#include <kanawha/kheap.h>
#include <kanawha/assert.h>

#define KHEAP_GROWTH_ORDER 21

// This assertion enforces that we stay aligned virtually
_Static_assert(KHEAP_GROWTH_ORDER <= CONFIG_HEAP_ALIGN_ORDER,
        "KHEAP_GROWTH_ORDER > CONFIG_HEAP_ALIGN_ORDER!");

struct kheap_free_region {
    ilist_node_t list_node;
    size_t size;
};

static void
kheap_dump(struct kheap *heap, printk_f *printer)
{
    ilist_node_t *free_region;
    ilist_for_each(free_region, &heap->free_list)
    {
        struct kheap_free_region *region =
            container_of(free_region, struct kheap_free_region, list_node);
        (*printer)("FREE [%p - %p)\n",
                (void*)region,
                (void*)region + region->size);
    }
}

static int
kheap_grow(
        struct kheap *heap)
{
    int res;
    dprintk("kheap_grow\n");

    size_t page_size = (1ULL << KHEAP_GROWTH_ORDER);
    if(heap->heap_size - heap->mapped < page_size) {
        return -ENOMEM;
    }

    paddr_t page_phys;
    res = page_alloc(KHEAP_GROWTH_ORDER, &page_phys, 0);
    if(res) {
        dprintk("kheap_grow failed to allocate heap page! (err=%s)\n", errnostr(res));
        return res;
    }

    vaddr_t page_virt = heap->vbase + heap->mapped;

    res = vmem_paged_region_map(
            heap->region,
            heap->mapped,
            page_phys,
            page_size,
            VMEM_REGION_WRITE|VMEM_REGION_READ|VMEM_REGION_EXEC);
    if(res) {
        dprintk("kheap_grow failed to map heap page! (err=%s)\n", errnostr(res));
        page_free(KHEAP_GROWTH_ORDER, page_phys);
        return res;
    }

    heap->mapped += page_size;

    res = kheap_free_specific(heap, (void*)page_virt, page_size);
    if(res) {
        return res;
    }

    return 0;
}

static int
kheap_shrink(struct kheap *heap)
{
    // TODO (LOCK ME)

    int res;
    size_t page_size = (1ULL << KHEAP_GROWTH_ORDER);
    if(heap->mapped < page_size) {
        return -EINVAL;
    }

    // We need a "translate" function to walk the
    // heap region page tables and determine what physical
    // page to free

    // heap->mapped -= (1ULL << KHEAP_GROWTH_ORDER);

    return -EUNIMPL;
}

static void
kheap_merge(struct kheap *heap)
{
    ilist_node_t *node;
    ilist_for_each(node, &heap->free_list)
    {
        struct kheap_free_region *cur, *next;
        cur = container_of(node, struct kheap_free_region, list_node);

        while(node) {
            if(node->next == &heap->free_list) {
                break;
            }

            next = container_of(node->next, struct kheap_free_region, list_node);

            dprintk("kheap_merge cur=%p, next=%p\n",
                    cur, next);


            uintptr_t cur_end = (uintptr_t)cur + cur->size;
            if(cur_end == (uintptr_t)next) {
                // We can merge the two regions
                cur->size += next->size;
                heap->num_free_regions--;
                ilist_remove(&heap->free_list, &next->list_node);
            }
//#ifdef DEBUG
            else if(cur_end > (uintptr_t)next) {
                // Something is wrong
                panic("kheap_merge found overlapping regions in the kheap free list! cur_end=%p, next=%p, free_list=%p\n",
                        (uintptr_t)cur_end, (uintptr_t)next, (uintptr_t)&heap->free_list);
                return;
            }
//#endif
            else {
                break;
            }
        }
    }
}

size_t kheap_amount_free(struct kheap *heap)
{
    size_t size = 0;
    ilist_node_t *node;
    ilist_for_each(node, &heap->free_list) {
        struct kheap_free_region *region =
            container_of(node, struct kheap_free_region, list_node);
        size += region->size;
    }
    return size;
}

void *
kheap_alloc_specific(struct kheap *heap, order_t align_order, size_t *size)
{
    ilist_node_t *node;

    struct kheap_free_region *best = NULL;
    size_t best_wasted = (size_t)-1;
    uintptr_t best_alloc_base;

    ilist_for_each(node,&heap->free_list) {
        struct kheap_free_region *region =
            container_of(node, struct kheap_free_region, list_node);

        DEBUG_ASSERT(KERNEL_ADDR(region));

        // Try to find the smallest free region that can fit our allocation
        if((region->size) >= *size) {
            uintptr_t region_end = (uintptr_t)region + region->size;
            uintptr_t alloc_base;
            alloc_base = (region_end - (uintptr_t)*size) & ~((1ULL<<align_order)-1ULL);
            if(alloc_base < (uintptr_t)region) {
                // Can't fit with alignment
                dprintk("Cannot use region of size: 0x%lx (not enough room for alignment padding)\n"
                        "(alloc_base=%p, region=%p)\n",
                        (unsigned long)region->size,
                        alloc_base, (uintptr_t)region);
                continue;
            }
            if(alloc_base != (uintptr_t)region 
              && (alloc_base - (uintptr_t)region) < sizeof(struct kheap_free_region)) {
                // Can't fit without losing track of some memory
                dprintk("Cannot use region of size: 0x%lx (would lose track of memory)\n",
                        (unsigned long)region->size);
                continue;
            }

            size_t wasted = (region_end - alloc_base) - *size;

            if(best == NULL 
             || wasted <= best_wasted
             || best->size > region->size) {
                best = region;
                best_wasted = wasted;
                best_alloc_base = alloc_base;
                dprintk("Using region: [%p-%p)\n",
                        (uintptr_t)region, (uintptr_t)region + region->size);
                if(wasted == 0 && region->size == *size) {
                    // We're not going to do any better
                    break;
                }
            }
        }
    }

    if(best == NULL) {
        // We need to increase the size of our heap
        dprintk("Growing heap\n");
        int res;
        struct kheap_free_region *end = NULL;
        do {
            res = kheap_grow(heap);
            if(res) {
                dprintk("kheap_alloc_specific: failed to grow heap!\n");
                return NULL;
            }
            DEBUG_ASSERT(!ilist_empty(&heap->free_list));

            end = container_of(heap->free_list.prev,
                               struct kheap_free_region,
                               list_node);
            DEBUG_ASSERT(KERNEL_ADDR(end));

            // We're still too small
            if((end->size) < *size) {
                continue;
            }

            // We could be large enough (alignment still needs to be checked though)
            uintptr_t region_base = (uintptr_t)end;
            uintptr_t region_end = region_base + end->size;

            // Allocate at the end of the region
            uintptr_t alloc_base = (region_end - (uintptr_t)*size);

            // Align down
            alloc_base &= ~((1ULL<<align_order)-1ULL);

            if(alloc_base < (uintptr_t)end) {
                // Can't fit with alignment
                continue;
            }

            if(alloc_base != (uintptr_t)end 
              && (alloc_base - (uintptr_t)end) < sizeof(struct kheap_free_region)) {
                // Can't fit without losing track of some memory
                continue;
            }

            // We can fit, we are the best automatically
            best_wasted = (region_end - alloc_base) - *size;
            best = end;
            best_alloc_base = alloc_base;

        } while(best == NULL);
    }

    // "best" must be non-null if we reached here
    DEBUG_ASSERT(KERNEL_ADDR(best));

    // Grow the region by the "wasted" bytes so we don't lose track of them
    *size += best_wasted;
    best->size -= *size;

    if(best->size < sizeof(struct kheap_free_region)) {
        // The region doesn't exist any more
        if(best->size != 0) {
            wprintk("kheap is losing track of 0x%lx bytes!\n", (unsigned long)best->size);
        }

        ilist_remove(&heap->free_list, &best->list_node);
    }

#ifdef CONFIG_DEBUG_KHEAP_TOUCH
    memset((void*)best_alloc_base, 0x55, *size);
#endif

    dprintk("kheap_alloc_specific -> [%p-%p)\n",
            best_alloc_base, best_alloc_base + *size);

    return (void*)best_alloc_base;
}

int
kheap_free_specific(struct kheap *heap, void *addr, size_t size)
{
    dprintk("kheap_free_specific <- [%p - %p)\n",
            addr, addr+size);
    
    if(size < sizeof(struct kheap_free_region)) {
        return -EINVAL;
    }

#ifdef CONFIG_DEBUG_KHEAP_TOUCH
    memset(addr, 0xAA, size);
#endif

    struct kheap_free_region *region = (struct kheap_free_region*)addr;
    region->size = size;

    ilist_node_t *node;
    ilist_for_each(node, &heap->free_list) {
        struct kheap_free_region *cmp =
            container_of(node, struct kheap_free_region, list_node);
        if((uintptr_t)region < (uintptr_t)cmp) {
            ilist_insert_before(&heap->free_list, &region->list_node, node);
            heap->num_free_regions++;
            kheap_merge(heap);
            return 0;
        }
    }

    ilist_push_tail(&heap->free_list, &region->list_node);
    heap->num_free_regions++;

    kheap_merge(heap);

    return 0;
}

static int
kheap_page_fault(
        struct vmem_region_ref *region,
        uintptr_t offset,
        unsigned long flags,
        void *priv_state)
{
    struct kheap *heap = priv_state;

    eprintk("kheap Page Fault! (heap=%p, offset=0x%llx)\n",
            heap, (ull_t)offset);

    return PAGE_FAULT_UNHANDLED;
}

int
kheap_init(
        struct kheap *heap,
        vaddr_t base,
        size_t size)
{
    int res;

    heap->vbase = base;
    heap->heap_size = size;
    heap->mapped = 0;
    heap->num_free_regions = 0;

    ilist_init(&heap->free_list);

    heap->region =
        vmem_region_create_paged(heap->heap_size, kheap_page_fault, (void*)heap);
    if(heap->region == NULL) {
        return -ENOMEM;
    }

    res = mem_flags_set_flags(
            get_virt_mem_flags(),
            (uintptr_t)heap->vbase,
            heap->heap_size,
            VIRT_MEM_FLAGS_HEAP);
    if(res) {
        return res;
    }

    res = vmem_force_mapping(heap->region, heap->vbase);
    if(res) {
        return res;
    }

    return 0;
}

