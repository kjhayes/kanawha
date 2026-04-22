
#include <drivers/term/8250/common.h>
#include <drivers/term/8250/term_dev.h>
#include <drivers/term/8250/uart.h>
#include <kanawha/assert.h>

int
generic_8250_set_irqs_enabled(struct uart_8250 *uart, int irqs)
{
    uint8_t ier = 0;
    if(irqs & UART_8250_IRQ_RECV_AVAIL)
    {
        ier |= 0b0001;
    }
    if(irqs & UART_8250_IRQ_XMIT_EMPTY)
    {
        ier |= 0b0010;
    }
    if(irqs & UART_8250_IRQ_RECV_STATUS)
    {
        ier |= 0b0100;
    }
    if(irqs & UART_8250_IRQ_MODEM_STATUS)
    {
        ier |= 0b1000;
    }
    uart_8250_write_reg(uart, UART_8250_IER, ier);
    return 0;
}

int
generic_8250_set_recv_trigger(struct uart_8250 *uart, size_t amount)
{
    uint8_t trigger_level;

    if(amount < 4)
    {
        trigger_level = 0b00; // Trigger on 1 byte
    }
    else if(amount < 8)
    {
        trigger_level = 0b01; // Triggers on 4 bytes
    }
    else if(amount < 14)
    {
        trigger_level = 0b10; // Triggers on 8 bytes
    }
    else
    {
        trigger_level = 0b11; // Triggers on 14 bytes
    }

    uint8_t fcr = ((trigger_level << 6) | 0b1);
    uart_8250_write_reg(uart, UART_8250_FCR, fcr);

    return 0;
}

int
register_uart_8250(const char *name,
                   struct uart_8250 *uart_8250,
                   struct uart_8250_ops *ops,
                   struct term_driver *term_driver,
                   struct uart_driver *uart_driver,
                   irq_handler_f *irq_handler)
{
    int res;

    DEBUG_ASSERT(name);
    DEBUG_ASSERT(uart_8250);
    DEBUG_ASSERT(ops);

    if(uart_8250->irq == NULL_IRQ)
    {
        wprintk("Cannot register 8250 UART without specified IRQ!\n");
        return -EINVAL;
    }
    struct irq_desc *irq_desc = irq_to_desc(uart_8250->irq);
    if(irq_desc == NULL)
    {
        wprintk("Cannot register 8250 UART with invalid IRQ %ld!\n",
                (sl_t)uart_8250->irq);
        return -ENXIO;
    }

    if(term_driver == NULL)
    {
        term_driver = &generic_8250_term_driver;
    }
    if(uart_driver == NULL)
    {
        uart_driver = &generic_8250_uart_driver;
    }
    if(irq_handler == NULL)
    {
        irq_handler = generic_8250_term_dev_irq_handler;
    }

    uart_8250->ops = ops;

    uart_8250->term_dev.driver = term_driver;
    uart_8250->uart.driver = uart_driver;

    res = register_term_dev(&uart_8250->term_dev, name);
    if(res)
    {
        return res;
    }

    uart_8250_set_recv_trigger(uart_8250, 1);

    uart_8250->irq_action =
        irq_install_handler(irq_desc, uart_8250, irq_handler);
    if(uart_8250->irq_action == NULL)
    {
        wprintk("Failed to install IRQ handler for 8250 UART: %s\n", name);
        unregister_term_dev(&uart_8250->term_dev);
        return -EINVAL;
    }

    unmask_irq(uart_8250->irq);

    uart_8250_set_irqs_enabled(uart_8250,
                               UART_8250_IRQ_RECV_AVAIL |
                                   UART_8250_IRQ_RECV_STATUS);

    return 0;
}

int
unregister_uart_8250(struct uart_8250 *uart_8250)
{
    int res;

    res = unregister_term_dev(&uart_8250->term_dev);
    if(res)
    {
        return res;
    }

    return 0;
}
