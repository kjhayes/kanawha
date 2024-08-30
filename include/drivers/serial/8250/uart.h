#ifndef __KANAWHA__UART_8250_UART_H__
#define __KANAWHA__UART_8250_UART_H__

#include <kanawha/uart.h>

int
generic_8250_uart_set_baudrate(
        struct uart *uart,
        baud_t rate);
int
generic_8250_uart_get_baudrate(
        struct uart *uart,
        baud_t *out);

int
generic_8250_uart_set_databits(
        struct uart *uart,
        uart_databits_t bits);
int
generic_8250_uart_get_databits(
        struct uart *uart,
        uart_databits_t *bits);

int
generic_8250_uart_set_stopbits(
        struct uart *uart,
        uart_stopbits_t bits);
int
generic_8250_uart_get_stopbits(
        struct uart *uart,
        uart_stopbits_t *bits);

int
generic_8250_uart_set_parity(
        struct uart *uart,
        uart_parity_t parity);
int
generic_8250_uart_get_parity(
        struct uart *uart,
        uart_parity_t *parity);

extern struct uart_driver generic_8250_uart_driver;

#endif
