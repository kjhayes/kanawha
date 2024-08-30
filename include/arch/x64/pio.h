#ifndef __KANAWHA__ARCH_X64_PIO_H__
#define __KANAWHA__ARCH_X64_PIO_H__

#include <kanawha/stdint.h>

typedef uint16_t pio_t;

static inline uint8_t  arch_inb(pio_t port)
{
    uint8_t val;
    asm volatile ("inb %w1, %b0" : "=a" (val) : "Nd" (port) : "memory");
    return val;
}
static inline uint16_t arch_inw(pio_t port)
{
    uint16_t val;
    asm volatile ("inw %w1, %w0" : "=a" (val) : "Nd" (port) : "memory");
    return val;
}
static inline uint32_t arch_inl(pio_t port)
{
    uint32_t val;
    asm volatile ("inl %w1, %0" : "=a" (val) : "Nd" (port) : "memory");
    return val;
}

static inline void arch_outb(pio_t port, uint8_t val)
{
    asm volatile ("outb %b0, %w1" :: "a" (val), "Nd" (port) : "memory");
}
static inline void arch_outw(pio_t port, uint16_t val)
{
    asm volatile ("outw %w0, %w1" :: "a" (val), "Nd" (port) : "memory");
}
static inline void arch_outl(pio_t port, uint32_t val)
{
    asm volatile ("outl %0, %w1" :: "a" (val), "Nd" (port) : "memory");
}

static inline void arch_piodelay(void)
{
    // Do an output on an unused port (this is what Linux does)
    arch_outb(0x80, 0);
}

#endif
