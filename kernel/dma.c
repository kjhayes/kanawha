
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/vmem.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>

static DECLARE_ILIST(dma_region_list);
static DECLARE_SPINLOCK(dma_region_list_lock);

#define DMA_MIN_REGION_ORDER (VMEM_MIN_PAGE_ORDER < PAGE_ALLOC_MIN_ORDER ? PAGE_ALLOC_MIN_ORDER : VMEM_MIN_PAGE_ORDER)

struct dma_free_block {
    ilist_node_t list_node;
    void __phys *phys_page;
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
    region->free_mem = 1ULL<<order;
    ilist_init(&region->free_list);
    region->order = order;

    res = page_alloc(
            order,
            &region->phys_page,
            page_flags);
    if(res) {
        kfree(region);
        return NULL;
    }

    struct dma_free_block *block = kmalloc(sizeof(struct dma_free_block));
    if(block == NULL) {
        page_free(order, region->phys_page);
        kfree(region);
        return NULL;
    }
    block->phys_page = region->phys_page;
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
        order_t align)
{
    int res;

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

    }

    order_t size_order = ((sizeof(size_t)*8)-1) - __builtin_clzll(size);

    order_t region_order;
    if(size_order < DMA_MIN_REGION_ORDER) {
        region_order = DMA_MIN_REGION_ORDER;
    } else {
        region_order = size_order;
    }

    struct dma_region *region =
        __add_dma_region(region_order, flags);

    spin_unlock(&dma_region_list_lock);
    return -ENOMEM;
}

int
dma_free(
        size_t size,
        dma_addr_t dma)
{
    return -EUNIMPL;
}

void __phys *
dma_phys_addr(dma_addr_t dma_addr)
{
    return (void __phys *)dma_addr.phys;
}

void *
dma_virt_addr(dma_addr_t dma_addr)
{
    return __va(dma_phys_addr(dma_addr));
}

