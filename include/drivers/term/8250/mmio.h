#ifndef __KANAWHA__DRIVERS_SERIAL_8250_MMIO_H__
#define __KANAWHA__DRIVERS_SERIAL_8250_MMIO_H__

#include <drivers/term/8250/common.h>
#include <kanawha/mmio.h>

struct mmio_uart_8250
{
    struct uart_8250 uart_8250;
    void __mmio *mmio_base;
    size_t mmio_size;
    int reg_shift;
};

// Keeps a reference to "name"
int
register_mmio_uart_8250(const char *name,
                        struct mmio_uart_8250 *uart,
                        void __mmio *mmio_base,
                        size_t mmio_size,
                        int reg_shift);

#endif
