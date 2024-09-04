
#include <kanawha/char_dev.h>
#include <kanawha/stddef.h>
#include <kanawha/irq_domain.h>
#include <drivers/serial/8250/common.h>

int
generic_8250_char_dev_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    dprintk("generic_8250_char_dev_irq_handler\n");
    return IRQ_NONE;
}

size_t
generic_8250_char_dev_read(
        struct char_dev *char_dev,
        void *buffer,
        size_t amount)
{
    struct uart_8250 *uart =
        container_of(char_dev, struct uart_8250, char_dev);

    dprintk("generic_8250_char_dev_read\n");

    if(amount <= 0) {
        return 0;
    }
    
    // Just testing for now, this shouldn't be allowed to block

    while((uart_8250_read_reg(uart, UART_8250_LSR) & 0x1) == 0);
    *(char*)buffer = uart_8250_read_reg(uart, UART_8250_RBR);

    return 1;
}

size_t
generic_8250_char_dev_write(
        struct char_dev *char_dev,
        void *buffer,
        size_t amount)
{
    struct uart_8250 *uart =
        container_of(char_dev, struct uart_8250, char_dev);

    dprintk("generic_8250_char_dev_write\n");

    if(amount <= 0) {
        return 0;
    }
 
    // Just testing for now, this shouldn't be allowed to block

    char c = *(char*)buffer;
    while((uart_8250_read_reg(uart, UART_8250_LSR) & 0x20) == 0);
    uart_8250_write_reg(uart, UART_8250_THR, c);

    return 1;
}

int
generic_8250_char_dev_flush(
        struct char_dev *char_dev)
{
    struct uart_8250 *uart =
        container_of(char_dev, struct uart_8250, char_dev);
    return -EUNIMPL;
}

struct char_driver 
generic_8250_char_driver = {
    .read = generic_8250_char_dev_read,
    .write = generic_8250_char_dev_write,
    .flush = generic_8250_char_dev_flush,
};

