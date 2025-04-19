
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/mmio.h>
#include <drivers/serial/8250/common.h>
#include <drivers/serial/8250/mmio.h>

static void
mmio_set_dlab(
        struct mmio_uart_8250 *uart,
        int dlab)
{
    uint8_t __mmio *icr_addr = uart->mmio_base + (3<<uart->reg_shift);
    uint8_t icr = mmio_readb(icr_addr);
    icr &= ~(1<<7);
    icr |= (!!dlab)<<7;
    mmio_writeb(icr_addr, icr);
}

static uint8_t __mmio *
enable_reg_addr(
        struct uart_8250 *gen_uart,
        reg_8250_t reg)
{
    struct mmio_uart_8250 *uart =
        container_of(gen_uart, struct mmio_uart_8250, uart_8250);

    switch(reg) {
        case UART_8250_RBR:
        case UART_8250_THR:
        case UART_8250_IER:
            mmio_set_dlab(uart, 0);
            break;
        case UART_8250_DLL:
        case UART_8250_DLM:
            mmio_set_dlab(uart, 1);
            break;
        default:
            break;
    }

    size_t offset;
    switch(reg) {
        case UART_8250_RBR:
        case UART_8250_THR:
        case UART_8250_DLL:
            offset = 0;
            break;
        case UART_8250_IER:
        case UART_8250_DLM:
            offset = 1;
            break;
        case UART_8250_IIR:
        case UART_8250_FCR:
            offset = 2;
            break;
        case UART_8250_LCR:
            offset = 3;
            break;
        case UART_8250_MCR:
            offset = 4;
            break;
        case UART_8250_LSR:
            offset = 5;
            break;
        case UART_8250_MSR:
            offset = 6;
            break;
        case UART_8250_SCR:
            offset = 7;
            break;
        default: offset = 0; break;
    }

    return uart->mmio_base + (offset<<uart->reg_shift);
}
static uint8_t
mmio_8250_read_reg(
        struct uart_8250 *uart,
        reg_8250_t reg)
{
    uint8_t __mmio *addr = enable_reg_addr(uart, reg);
    return mmio_readb(addr);
}

static void
mmio_8250_write_reg(
        struct uart_8250 *uart,
        reg_8250_t reg,
        uint8_t value)
{
    uint8_t __mmio *addr = enable_reg_addr(uart, reg);
    mmio_writeb(addr, value);
}

static struct uart_8250_ops
mmio_uart_8250_ops = {
    .read_reg = mmio_8250_read_reg,
    .write_reg = mmio_8250_write_reg,
};

int
register_mmio_uart_8250(
        const char *name,
        struct mmio_uart_8250 *uart,
        void __mmio *mmio_base,
        size_t mmio_size,
        int reg_shift)
{
    int res;

    uart->mmio_base = mmio_base;
    uart->mmio_size = mmio_size;
    uart->reg_shift = reg_shift;

    res = register_uart_8250(
            name,
            &uart->uart_8250,
            &mmio_uart_8250_ops,
            NULL,
            NULL);
    if(res) {
        return res;
    }

    return 0;
}

