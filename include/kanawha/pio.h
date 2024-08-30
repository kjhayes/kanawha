#ifndef __KANAWHA__PIO_H__
#define __KANAWHA__PIO_H__

#ifndef CONFIG_PORT_IO
#error Included File "kanawha/pio.h" without having CONFIG_PORT_IO set!
#endif

#include <kanawha/stdint.h>

#ifdef CONFIG_X64
#include <arch/x64/pio.h>
#endif

extern uint8_t  arch_inb(pio_t);
extern uint16_t arch_inw(pio_t);
extern uint32_t arch_inl(pio_t);

extern void arch_outb(pio_t, uint8_t);
extern void arch_outw(pio_t, uint16_t);
extern void arch_outl(pio_t, uint32_t);

static inline uint8_t
inb(pio_t port) {
    return arch_inb(port);
};

static inline uint16_t
inw(pio_t port) {
    return arch_inw(port);
};

static inline uint32_t
inl(pio_t port) {
    return arch_inl(port);
};

static inline void 
outb(pio_t port, uint8_t val) {
    arch_outb(port, val);
};

static inline void 
outw(pio_t port, uint16_t val) {
    arch_outw(port, val);
};

static inline void 
outl(pio_t port, uint32_t val) {
    arch_outl(port, val);
};

static inline void
piodelay(void) {
    arch_piodelay();
}

#endif
