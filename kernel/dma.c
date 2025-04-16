
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/vmem.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>

static DECLARE_ILIST(dma_region_list);
static DECLARE_SPINLOCK(dma_region_list_lock);

#define DMA_MIN_REGION_ORDER \
    (VMEM_MIN_PAGE_ORDER < PAGE_ALLOC_MIN_ORDER \
     ? PAGE_ALLOC_MIN_ORDER : VMEM_MIN_PAGE_ORDER)

struct dma_free_block
{
    ilist_node_t list_node;
    void __phys *phys_base;
    size_t size;
};

struct dma_region
{
    ilist_node_t list_node;

    void __phys *phys_page;
    order_t order;

    unsigned long dma_flags;

    size_t free_mem;
    ilist_t free_list;
};

static struct dma_region *
__add_dma_region(
        order_t order,
        unsigned long dma_flags)
{
    int res;

    unsigned long page_flags = 0;
    if(dma_flags & DMA_PHYS_16) {
        page_flags |= PAGE_ALLOC_16BIT;
    }
    if(dma_flags & DMA_PHYS_32) {
        page_flags |= PAGE_ALLOC_32BIT;
    }

    struct dma_region *region = kmalloc(sizeof(struct dma_region));
    if(region == NULL) {
        return NULL;
    }
    region->dma_flags = dma_flags;
    region->order = order;
    region->free_mem = 1ULL<<region->order;
    ilist_init(&region->free_list);

    res = page_alloc(
            region->order,
            &region->phys_page,
            page_flags);
    if(res) {
        kfree(region);
        return NULL;
    }

    dprintk("__add_dma_region: page_alloc(order=%ld) -> %p\n",
            (sl_t)region->order, region->phys_page);

    struct dma_free_block *block = kmalloc(sizeof(struct dma_free_block));
    if(block == NULL) {
        page_free(order, region->phys_page);
        kfree(region);
        return NULL;
    }
    block->phys_base = region->phys_page;
    block->size = 1ULL<<region->order;

    ilist_push_tail(&region->free_list, &block->list_node);

    ilist_push_tail(&dma_region_list, &region->list_node);

    return region;
}

static int
__free_dma_region(
        struct dma_region *region)
{
    int res;

    ilist_remove(&dma_region_list, &region->list_node);

    while(1) {
        ilist_node_t *node;
        node = ilist_pop_tail(&region->free_list);
        if(node == NULL) {
            break;
        }
        struct dma_free_block *blk =
            container_of(node, struct dma_free_block, list_node);
        kfree(blk);
    }

    page_free(region->order, region->phys_page);
    kfree(region);

    return 0;
}

static int
__dma_region_alloc(
        struct dma_region *region,
        size_t size,
        order_t align,
        void __phys **out)
{
    int res;

    ilist_node_t *free_node;
    ilist_for_each(free_node, &region->free_list) {
        struct dma_free_block *blk =
            container_of(free_node, struct dma_free_block, list_node);
        if(blk->size < size) {
            continue;
        }
        uintptr_t phys_base = (uintptr_t)blk->phys_base;
        uintptr_t phys_end = (uintptr_t)blk->phys_base + blk->size;
        uintptr_t align_mask = ((1ULL<<align)-1);
        if((phys_base & align_mask) == 0) {
            // Start of region is aligned
            dprintk("__dma_region_alloc: At Start\n");
            blk->phys_base += size;
            blk->size -= size;
            *out = (void __phys *)phys_base;
        }
        else if(((phys_end - size) & align_mask) == 0) {
            // End of region is aligned
            dprintk("__dma_region_alloc: At End\n");
            blk->size -= size;
            *out = (void __phys *)(phys_end - size);
        }
        else {
            continue; // Don't try splitting blocks
//            dprintk("__dma_region_alloc: Doubly Mis-Aligned\n");
//            size_t misalign_below = (1ULL<<align) - (phys_base & align_mask);
//            size_t misalign_above = (phys_end - size) & align_mask;
//            size_t total_size = blk->size;
//
//            struct dma_free_block *above = kmalloc(sizeof(struct dma_free_block));
//            if(above == NULL) {
//                // Not enough memory to split the block in two
//                continue;
//            }
//
//            // Is it better to keep one large block and one tiny block,
//            // or try to keep two medium sized blocks? (I'm not sure, but we'll go with the latter)
//            if(misalign_below > misalign_above)
//            {
//                *out = (void __phys *)phys_base + misalign_below;
//            }
//            else
//            {
//                *out = (void __phys *)(phys_end - (size + misalign_above));
//            }
//
//            above->phys_base = (*out + size);
//            above->size = (uintptr_t)phys_end - (uintptr_t)above->phys_base;
//
//            blk->size = (uintptr_t)(*out) - phys_base;
//
//            ilist_push_tail(&region->free_list, &above->list_node);
        }

        if(blk->size == 0) {
            ilist_remove(&region->free_list, free_node);
            kfree(free_node);
        }

        return 0;
    }

    return -ENOMEM;
}

static int
__dma_region_free(
        struct dma_region *region,
        void __phys *base,
        size_t size)
{
    uintptr_t free_base = (uintptr_t)base;
    uintptr_t free_end = (uintptr_t)base + size;

    size_t region_size = 1ULL << region->order;
    uintptr_t region_base = (uintptr_t)region->phys_page;
    uintptr_t region_end = region_base + region_size;

    DEBUG_ASSERT(region_base <= (uintptr_t)base);
    DEBUG_ASSERT(region_end >= (uintptr_t)base + size);

    region->free_mem += size;
    if(region->free_mem == (1ULL<<region->order)) {
        // Free the entire region
        int res = __free_dma_region(region);
        if(res) {
            region->free_mem -= size;
            return res;
        }
        return 0;
    }

    // Look for regions which we can merge with
    struct dma_free_block *blk_below = NULL;
    struct dma_free_block *blk_above = NULL;

    ilist_node_t *iter;
    ilist_for_each(iter, &region->free_list)
    {
        struct dma_free_block *blk =
            container_of(iter, struct dma_free_block, list_node);

        if((uintptr_t)blk->phys_base == free_end) {
            DEBUG_ASSERT(blk_above == NULL);
            blk_above = blk;
            if(blk_below) {
                break;
            }
            continue;
        }
        if((uintptr_t)blk->phys_base + blk->size == free_base) {
            DEBUG_ASSERT(blk_below == NULL);
            blk_below = blk;
            if(blk_above) {
                break;
            }
            continue;
        }
    }

    if(blk_above == NULL && blk_below == NULL) {
        struct dma_free_block *blk = kmalloc(sizeof(struct dma_free_block));
        if(blk == NULL) {
            region->free_mem -= size;
            return -ENOMEM;
        }
        blk->phys_base = base;
        blk->size = size;
        ilist_push_tail(&region->free_list, &blk->list_node);
    } else if(blk_above == NULL) {
        // blk_below is valid
        blk_below->size += size;
    } else if(blk_below == NULL) {
        // blk_above is valid
        blk_above->size += size;
        blk_above->phys_base -= size;
    } else {
        // both blk_above and blk_below are valid
        blk_below->size += size;
        ilist_remove(&region->free_list, &blk_above->list_node);
        kfree(blk_above);
    }

    return 0;
}

int
dma_alloc(
        size_t size,
        order_t align_order,
        unsigned long flags,
        dma_addr_t * dma_out)
{
    int res;

    if(size == 0) {
        return -EINVAL;
    }

    spin_lock(&dma_region_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &dma_region_list) {
        struct dma_region *region =
            container_of(node, struct dma_region, list_node);
        if(region->dma_flags != flags) {
            continue;
        }

        void __phys *phys_base;
        res = __dma_region_alloc(
                region,
                size,
                align_order,
                &phys_base);
        if(res) {
            continue;
        }

        *dma_out = (dma_addr_t)phys_base;
        goto exit;
    }

    order_t size_order = ((sizeof(size_t)*8)-1) - __builtin_clzll(size);

    order_t region_order;
    if(size_order < DMA_MIN_REGION_ORDER) {
        region_order = DMA_MIN_REGION_ORDER;
    } else {
        region_order = size_order+1;
    }

    if(region_order < align_order) {
        region_order = align_order+1;
    }

    struct dma_region *region =
        __add_dma_region(region_order, flags);

    if(region == NULL) {
        spin_unlock(&dma_region_list_lock);
        return -ENOMEM;
    }

    void __phys *phys_base;
    res = __dma_region_alloc(
            region,
            size,
            align_order,
            &phys_base);
    if(res) {
        spin_unlock(&dma_region_list_lock);
        return res;
    }

    *dma_out = (dma_addr_t)phys_base;

exit:
    dprintk("dma_alloc: [%p - %p) -> [%p - %p)\n",
            dma_virt_addr(*dma_out),
            dma_virt_addr(*dma_out) + size,
            dma_phys_addr(*dma_out),
            dma_phys_addr(*dma_out) + size);

    spin_unlock(&dma_region_list_lock);
    return 0;
}

int
dma_free(
        dma_addr_t addr,
        size_t size)
{
    ilist_node_t *iter;

    void __phys *phys_addr = addr;
    uintptr_t base = (uintptr_t)addr;
    uintptr_t end = (uintptr_t)base + size;

    dprintk("dma_free: [%p - %p)\n",
            dma_phys_addr(addr),
            dma_phys_addr(addr) + size);

    spin_lock(&dma_region_list_lock);
    ilist_for_each(iter, &dma_region_list)
    {
        struct dma_region *region =
            container_of(iter, struct dma_region, list_node);
        uintptr_t region_base = (uintptr_t)region->phys_page;
        uintptr_t region_end = (uintptr_t)region_base + (1ULL<<region->order);
        if(region_base <= base && region_end >= end) {
            int res = __dma_region_free(region, phys_addr, size);
            spin_unlock(&dma_region_list_lock);
            if(res) {
                return res;
            }
            return 0;
        }
    }
    spin_unlock(&dma_region_list_lock);

    return -EINVAL;
}

void __phys *
dma_phys_addr(dma_addr_t dma_addr)
{
    return (void __phys *)dma_addr;
}

void *
dma_virt_addr(dma_addr_t dma_addr)
{
    return __va(dma_phys_addr(dma_addr));
}

