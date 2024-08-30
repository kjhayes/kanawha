#ifndef __KANAWHA__MMIO_H__
#define __KANAWHA__MMIO_H__

#include <kanawha/stdint.h>

#define __mmio __attribute__((noderef))

void __mmio *mmio_map(paddr_t paddr, size_t size);
int mmio_unmap(void __mmio *addr, size_t size);

struct vmem_region *
mmio_vmem_region(void);

/*
 * MMIO Accessors
 */

static inline uint8_t
mmio_readb(void __mmio *addr) {
    return *(volatile uint8_t*)addr;
}
static inline uint16_t
mmio_readw(void __mmio *addr)
{
    return *(volatile uint16_t*)addr;
}
static inline uint32_t
mmio_readl(void __mmio *addr)
{
    return *(volatile uint32_t*)addr;
}
static inline uint64_t
mmio_readq(void __mmio *addr)
{
    return *(volatile uint64_t*)addr;
}

static inline void
mmio_writeb(void __mmio *addr, uint8_t val)
{
    *(volatile uint8_t*)addr = val;
}
static inline void
mmio_writew(void __mmio *addr, uint16_t val)
{
    *(volatile uint16_t*)addr = val;
}
static inline void
mmio_writel(void __mmio *addr, uint32_t val)
{
    *(volatile uint32_t*)addr = val;
}
static inline void
mmio_writeq(void __mmio *addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

#endif
