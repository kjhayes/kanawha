#ifndef __KANAWHA__DMA_H__
#define __KANAWHA__DMA_H__

#include <kanawha/stdint.h>
#include <kanawha/vmem.h>

typedef struct {
    void __phys *phys;
    struct dma_region *region;
} dma_addr_t;

#define DMA_PHYS_16 (1ULL<<0)
#define DMA_PHYS_32 (1ULL<<1)
#define DMA_PHYS_64 (1ULL<<2)

int
dma_alloc(
        size_t size,
        order_t align,
        unsigned long flags,
        dma_addr_t *out);

int
dma_free(
        size_t size,
        dma_addr_t dma);

void __phys *
dma_phys_addr(dma_addr_t dma_addr);
void *
dma_virt_addr(dma_addr_t dma_addr);

#endif
