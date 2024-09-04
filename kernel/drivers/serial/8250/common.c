
#include <drivers/serial/8250/common.h>
#include <drivers/serial/8250/uart.h>
#include <drivers/serial/8250/char_dev.h>
#include <kanawha/assert.h>

int
register_uart_8250(
        const char *name,
        struct device *device,
        struct uart_8250 *uart_8250,
        struct uart_8250_ops *ops,
        struct char_driver *char_driver,
        struct uart_driver *uart_driver)
{
    int res;

    DEBUG_ASSERT(name);
    DEBUG_ASSERT(device);
    DEBUG_ASSERT(uart_8250);
    DEBUG_ASSERT(ops);

    if(char_driver == NULL) {
        char_driver = &generic_8250_char_driver;
    }
    if(uart_driver == NULL) {
        uart_driver = &generic_8250_uart_driver;
    }

    uart_8250->ops = ops;

    res = register_char_dev(
            &uart_8250->char_dev,
            name,
            char_driver,
            device);
    if(res) {
        return res;
    }

    return 0;
}

int
unregister_uart_8250(
        struct uart_8250 *uart_8250)
{
    int res;

    res = unregister_char_dev(&uart_8250->char_dev);
    if(res) {
        return res;
    }

    return 0;
}

