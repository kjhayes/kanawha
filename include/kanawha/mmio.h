#ifndef __KANAWHA__MMIO_H__
#define __KANAWHA__MMIO_H__

#include <kanawha/attribute.h>
#include <kanawha/pointer.h>
#include <kanawha/string.h>
#include <kanawha/types.h>
#include <kanawha/assert.h>

#define __mmio __noderef

void __mmio *
mmio_map(void __phys *paddr, size_t size);
int
mmio_unmap(void __mmio *addr, size_t size);

struct vmem_region *
mmio_vmem_region(void);

int
mmio_check_mapped(
        void __mmio *addr,
        unsigned long size);

/*
 * MMIO Accessors
 */

static inline uint8_t
mmio_readb(void __mmio *addr)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(uint8_t)) == 0);
    return *(volatile uint8_t *)addr;
}
static inline uint16_t
mmio_readw(void __mmio *addr)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(uint16_t)) == 0);
    return *(volatile uint16_t *)addr;
}
static inline uint32_t
mmio_readl(void __mmio *addr)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(uint32_t)) == 0);
    return *(volatile uint32_t *)addr;
}
static inline uint64_t
mmio_readq(void __mmio *addr)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(uint64_t)) == 0);
    return *(volatile uint64_t *)addr;
}

static inline void
mmio_writeb(void __mmio *addr, uint8_t val)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(val)) == 0);
    *(volatile uint8_t *)addr = val;
}
static inline void
mmio_writew(void __mmio *addr, uint16_t val)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(val)) == 0);
    *(volatile uint16_t *)addr = val;
}
static inline void
mmio_writel(void __mmio *addr, uint32_t val)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(val)) == 0);
    *(volatile uint32_t *)addr = val;
}
static inline void
mmio_writeq(void __mmio *addr, uint64_t val)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, sizeof(val)) == 0);
    *(volatile uint64_t *)addr = val;
}

static inline void
mmio_memset(void __mmio *addr, int val, size_t length)
{
    DEBUG_ASSERT(mmio_check_mapped(addr, length) == 0);
    memset((void *)addr, val, length);
}

#endif
