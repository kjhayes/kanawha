

#include <kanawha/init.h>
#include <kanawha/percpu.h>
#include <kanawha/cpu.h>
#include <kanawha/mem_flags.h>
#include <kanawha/kmalloc.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/thread.h>

static DECLARE_SPINLOCK(percpu_heap_lock);

static size_t percpu_data_size = 0;
static DECLARE_ILIST(percpu_heap_list);
static DECLARE_ILIST(percpu_heap_free_list);

#ifdef CONFIG_PERCPU_DEBUG_ASSERTIONS
DECLARE_PERCPU_VAR(uint64_t, __percpu_assert_checksum);
#endif

struct percpu_heap
{
    struct vmem_region *region;
    void *vbase;

    size_t num_pages;
    struct cpu *cpu;

    ilist_node_t list_node;
};

struct percpu_heap_free_region
{
    uintptr_t start_offset;
    size_t size;

    ilist_node_t list_node;
};

extern uint8_t __builtin_kpercpu_start[];
extern uint8_t __builtin_kpercpu_end[];

#define PERCPU_BASE ((void __percpu *)__builtin_kpercpu_start)

static int
static_bsp_init_builtin_percpu(void) 
{
    int res;

    percpu_data_size = (uintptr_t)__builtin_kpercpu_end - (uintptr_t)__builtin_kpercpu_start;
    dprintk("kpercpu_start = %p, kpercpu_end = %p\n",
            __builtin_kpercpu_start,
            __builtin_kpercpu_end);
    printk("builtin percpu size: %ld bytes\n", percpu_data_size);

    // CPU 0 (the BSP) just uses the inplace percpu section for builtin percpu variables
    // during boot (eventually we will need to transfer to a percpu heap to allow allocations)
    res = arch_set_percpu_area(0, (void*)__builtin_kpercpu_start);
    if(res) {
        return res;
    }

    res = set_current_cpu_id(0);
    if(res) {
        return res;
    }

#ifdef CONFIG_PERCPU_DEBUG_ASSERTIONS
    *(uint64_t*)percpu_ptr(percpu_addr(__percpu_assert_checksum)) =
        ((uint64_t)PERCPU_DEBUG_CHECKSUM << 32) | 0;
#endif

    return 0;
}

declare_init_desc(static, static_bsp_init_builtin_percpu, "Initializing BSP builtin percpu Variables");

// Transfer from the early state setup in static_bsp_init_builtin_percpu,
// to using an actual percpu heap on the BSP.
static int
bsp_transfer_to_percpu_heap(struct cpu *bsp)
{
    struct thread_state *cur_thread = current_thread();

    if(bsp->id != current_cpu_id()) {
        eprintk("Tried calling bsp_transfor_to_percpu_heap on AP!\n");
        return -EINVAL;
    }

    size_t size = (uintptr_t)__builtin_kpercpu_end - (uintptr_t)__builtin_kpercpu_start;
    printk("Copying perpcu data area of BSP [%p - %p) to percpu heap [%p - %p)\n",
            __builtin_kpercpu_start, __builtin_kpercpu_end,
            bsp->percpu_data, bsp->percpu_data + size);

    memcpy(bsp->percpu_data, (void*)__builtin_kpercpu_start, (uintptr_t)__builtin_kpercpu_end - (uintptr_t)__builtin_kpercpu_start);

    dprintk("bsp->percpu_data=%p\n", bsp->percpu_data);
    int res = arch_set_percpu_area(bsp->id, bsp->percpu_data);
    if(res) {
        panic("BSP Failed to transfer to percpu heap! (err=%s)\n",
                errnostr(res));
    }

    cpu_id_t bsp_id = current_cpu_id();
    if(bsp_id != bsp->id) {
        panic("Corrupted percpu data area when transferring BSP to percpu heap!\n");
    }

    if(current_thread() != cur_thread) {
        panic("Corrupted percpu data area when transferring BSP to percpu heap! "
              "(old thread=%p, corrupted thread = %p\n",
                 cur_thread, current_thread());
    }

    // In-case the architecture doesn't uses a different mechanism for remote CPU's still
    // place this call
    res = arch_set_percpu_area_remote(bsp->id, bsp->percpu_data);
    if(res) {
        return res;
    }

    return 0;
}

static int
percpu_heap_set_size(struct percpu_heap *heap, size_t size)
{
    size_t num_pages = size >> VMEM_MIN_PAGE_ORDER;
    if(num_pages << VMEM_MIN_PAGE_ORDER != size) {
        num_pages++;
    }
    dprintk("num_pages = %p\n", num_pages);

    if(num_pages > heap->num_pages) {
        // Growing
        for(size_t page = heap->num_pages; page < num_pages; page++) {
            paddr_t page_phys;
            int res = page_alloc(VMEM_MIN_PAGE_ORDER, &page_phys, 0);
            if(res) {
                return res;
            }

            vaddr_t page_virt = __va(page_phys);
            memset((void*)page_virt, 0, (1ULL<<VMEM_MIN_PAGE_ORDER));

            res = vmem_paged_region_map(
                    heap->region,
                    page << VMEM_MIN_PAGE_ORDER,
                    page_phys,
                    1ULL << VMEM_MIN_PAGE_ORDER,
                    VMEM_REGION_READ|VMEM_REGION_WRITE);
            if(res) {
                page_free(VMEM_MIN_PAGE_ORDER, page_phys);
                return res;
            }
        }
        heap->num_pages = num_pages;
    } else if(num_pages < heap->num_pages) {
        // Shrinking
        return -EUNIMPL;
    } else {
        // Already fit
    }

    return 0;
}

static int
percpu_heap_page_fault_handler(
        struct vmem_region_ref *ref,
        uintptr_t offset,
        unsigned long pf_flags,
        void *priv_state)
{
    struct percpu_heap *heap = priv_state;

    eprintk("CPU (%ld) percpu Heap Page Fault! (offset=0x%llx)\n",
            (sl_t)heap->cpu->id, (ull_t)offset);

    return PAGE_FAULT_UNHANDLED;
}

int
init_cpu_percpu_data(struct cpu *cpu)
{
    int res;

    struct percpu_heap *heap = kmalloc(sizeof(struct percpu_heap));
    if(heap == NULL) {
        return -ENOMEM;
    }
    memset(heap, 0, sizeof(struct percpu_heap));

    heap->num_pages = 0;
    heap->cpu = cpu;

    // Find a virtual memory region to use for this CPU's percpu area
    uintptr_t vbase;
    res = mem_flags_find_and_reserve(
            get_virt_mem_flags(),
            (1ULL<<CONFIG_PERCPU_HEAP_SIZE_ORDER),
            CONFIG_HEAP_ALIGN_ORDER,
            VIRT_MEM_FLAGS_AVAIL|VIRT_MEM_FLAGS_HIGHMEM,
            VIRT_MEM_FLAGS_NONCANON,
            VIRT_MEM_FLAGS_HEAP|VIRT_MEM_FLAGS_PERCPU,
            VIRT_MEM_FLAGS_AVAIL,
            &vbase);
    if(res) {
        kfree(heap);
        eprintk("Failed to find virtual memory region to put percpu heap!\n");
        return res;
    }


    cpu->percpu_data = (void*)vbase;
    dprintk("cpu->percpu_data=%p\n", cpu->percpu_data);

    heap->vbase = (void*)vbase;
    heap->region =
        vmem_region_create_paged(
                1ULL<<CONFIG_PERCPU_HEAP_SIZE_ORDER,
                percpu_heap_page_fault_handler,
                (void*)heap);
    if(heap->region == NULL) {
        kfree(heap);
        return -ENOMEM;
    }
    
    res = vmem_force_mapping(heap->region, (vaddr_t)heap->vbase);
    if(res) {
        vmem_region_destroy(heap->region);
        kfree(heap);
        return res;
    }

    spin_lock(&percpu_heap_lock);

    ilist_push_tail(&percpu_heap_list, &heap->list_node);
    res = percpu_heap_set_size(heap, percpu_data_size);
    if(res) {
        spin_unlock(&percpu_heap_lock);
        return res;
    }

    spin_unlock(&percpu_heap_lock);


    printk("Initialized CPU %d percpu Heap [%p - %p)\n",
            cpu->id,
            heap->vbase,
            heap->vbase + (1ULL<<CONFIG_PERCPU_HEAP_SIZE_ORDER));

    if(cpu->is_bsp) {
        int res = bsp_transfer_to_percpu_heap(cpu);
        if(res) {
            return res;
        }
    } else {
        int res = arch_set_percpu_area_remote(cpu->id, cpu->percpu_data);
        if(res) {
            return res;
        }

#ifdef CONFIG_PERCPU_DEBUG_ASSERTIONS
    *(uint64_t*)percpu_ptr_specific(percpu_addr(__percpu_assert_checksum), cpu->id) =
        ((uint64_t)PERCPU_DEBUG_CHECKSUM << 32) | (uint32_t)cpu->id;
#endif
    }

    return 0;
}

/*
 * These are not fast, with the percpu heaps we are more focused on saving space,
 * because the percpu heap(s) are much more limited than the kmalloc heap
 */

// Forward declaration of version which assumes lock is already held
static int
__percpu_free(void __percpu *ptr, size_t size);

// Assumes we already hold the percpu_heap_lock
int __percpu_grow_heaps(size_t size)
{
    if(size < (1UL<<KMALLOC_ALIGN_ORDER)) {
        // Otherwise our heap free-list becomes way too fragmented
        size = (1UL<<KMALLOC_ALIGN_ORDER);
    }

    ilist_node_t *heap_node;
    percpu_data_size += size;
    ilist_for_each(heap_node, &percpu_heap_list) {
        struct percpu_heap *heap =
            container_of(heap_node, struct percpu_heap, list_node);
        int res = percpu_heap_set_size(heap, percpu_data_size);
        if(res) {
            return res;
        } 
    }

    void __percpu *base = PERCPU_BASE + (percpu_data_size - size);
    int res = __percpu_free(base, size);
    if(res) {
        return res;
    }

    return 0;
}

#define PERCPU_HEAP_MAX_GROW_STEP PAGE_SIZE_2MB

void __percpu *
percpu_alloc(size_t size)
{
    spin_lock(&percpu_heap_lock);

    if(size < (1UL<<KMALLOC_ALIGN_ORDER)) {
        // Otherwise our heap free-list becomes way too fragmented
        size = (1UL<<KMALLOC_ALIGN_ORDER);
    }

    void __percpu *ptr = PERCPU_NULL;
    while(ptr == PERCPU_NULL) {

    struct percpu_heap_free_region *final_region = NULL;

    void __percpu *base;
    struct percpu_heap_free_region *to_use = NULL;
    ilist_node_t *node;

    ilist_for_each(node, &percpu_heap_free_list) {
        struct percpu_heap_free_region *region =
            container_of(node, struct percpu_heap_free_region, list_node);

        base = PERCPU_BASE + region->start_offset;

        size_t usable_size = region->size;

        // Align the base
        if((uintptr_t)base & ((1ULL<<KMALLOC_ALIGN_ORDER)-1)) {
            size_t misalign = (1ULL<<KMALLOC_ALIGN_ORDER) - ((uintptr_t)base & ((1ULL<<KMALLOC_ALIGN_ORDER)-1));
            if(misalign >= usable_size) {
                continue;
            }
            base += misalign;
            usable_size -= misalign;
        }

        if(usable_size >= size) {
            to_use = region;
            break;
        }
    }

    if(to_use == NULL) {
        // Grow the heap and try again
        int res = __percpu_grow_heaps(size < PERCPU_HEAP_MAX_GROW_STEP ? size : PERCPU_HEAP_MAX_GROW_STEP);
        if(res) {
            spin_unlock(&percpu_heap_lock);
            return PERCPU_NULL;
        }
        continue;
    }

    void __percpu* to_use_start = PERCPU_BASE + to_use->start_offset;
    void __percpu* to_use_end = to_use_start + to_use->size;

    if(base != to_use_start) {
        // Cover top half
        to_use->size = (uintptr_t)base - (uintptr_t)to_use_start;
        if(to_use_end != base + size) {
            // Split region into two pieces
            struct percpu_heap_free_region *after_region = kmalloc(sizeof(struct percpu_heap_free_region));
            if(after_region == NULL) {
                return PERCPU_NULL;
            }
            after_region->start_offset = (base + size) - PERCPU_BASE;
            after_region->size = to_use_end - (base + size);
            ilist_push_tail(&percpu_heap_free_list, &after_region->list_node);
        }
    } else if(to_use_end != base + size) {
        // Cover bottom half
        to_use->size -= size;
        to_use->start_offset = (uintptr_t)(base + size);
    } else {
        // Fully cover the region
        ilist_remove(&percpu_heap_free_list, &to_use->list_node);
        kfree(to_use);
    }

    ptr = base;

    }

    spin_unlock(&percpu_heap_lock);

    return ptr;
}

static int
__percpu_free(void __percpu *ptr, size_t size)
{
    if(size < (1UL<<KMALLOC_ALIGN_ORDER)) {
        // Otherwise our heap free-list becomes way too fragmented
        size = (1UL<<KMALLOC_ALIGN_ORDER);
    }

    uintptr_t start = (uintptr_t)ptr - (uintptr_t)__builtin_kpercpu_start;
    uintptr_t end = start + size;

    dprintk("__percpu_free(ptr=%p, size=%p)\n", ptr, size);
    dprintk("\tstart=%p, end=%p\n", start, end);

    struct percpu_heap_free_region *before = NULL, *after = NULL;
    ilist_node_t *node;
    ilist_for_each(node, &percpu_heap_free_list) {
        struct percpu_heap_free_region *region =
            container_of(node, struct percpu_heap_free_region, list_node);
        dprintk("Comparing to region start=%p, end=%p\n",
                region->start_offset, region->start_offset + region->size);
        if(region->start_offset == end) {
            dprintk("Found After!\n");
            if(after == NULL) {
                after = region;
                if(before != NULL) {
                    break;
                }
            } else {
                eprintk("percpu heap corrupted! (multiple free regions have same start_offset)\n");
                return -EINVAL;
            }
        }
        if(region->start_offset + region->size == start) {
            dprintk("Found Before!\n");
            if(before == NULL) {
                before = region;
                if(after != NULL) {
                    break;
                }
            } else {
                eprintk("percpu heap corrupted! (multiple free regions have same end_offset)\n");
                return -EINVAL;
            }
        }
    }

    if(after != NULL) {
        size += after->size;
        dprintk("Consuming After Region\n");
        ilist_remove(&percpu_heap_free_list, &after->list_node);
    }

    if(before != NULL) {
        dprintk("Merging into before region\n");
        if(after != NULL) {
            dprintk("Freeing After Region\n");
            kfree(after);
        }
        before->size += size;
    } else {
        // before == NULL
        dprintk("Need to allocate a new free region\n");
        struct percpu_heap_free_region *region =
            after != NULL ? after : kmalloc(sizeof(struct percpu_heap_free_region));

        if(region == NULL) {
            return -ENOMEM;
        }

        if(region == after) {
            dprintk("Can use exisitng After region\n");
        }

        region->size = size;
        region->start_offset = start;
        ilist_push_tail(&percpu_heap_free_list, &region->list_node);
    }

    return 0;
}

void
percpu_free(void __percpu *ptr, size_t size)
{
    spin_lock(&percpu_heap_lock);
    int res = __percpu_free(ptr, size);
    if(res) {
        panic("__percpu_free failed! (err=%s)\n",
                errnostr(res));
    }
    spin_unlock(&percpu_heap_lock);
}

void __percpu *
percpu_calloc(size_t size)
{

    void __percpu *ptr = percpu_alloc(size);
    if(ptr == PERCPU_NULL) {
        return ptr;
    }

    spin_lock(&percpu_heap_lock);
    ilist_node_t *node;
    ilist_for_each(node, &percpu_heap_list) {
        struct percpu_heap *heap =
            container_of(node, struct percpu_heap, list_node);
        void *ptr_spec = heap->vbase + (ptr - PERCPU_BASE);
        memset(ptr_spec, 0, size);
    }
    spin_unlock(&percpu_heap_lock);

    return ptr;
}

