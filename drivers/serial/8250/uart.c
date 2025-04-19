
#include <kanawha/uart.h>
#include <kanawha/stddef.h>
#include <kanawha/errno.h>
#include <drivers/serial/8250/uart.h>
#include <drivers/serial/8250/common.h>

int
generic_8250_uart_set_baudrate(
        struct uart *uart,
        baud_t rate)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);

    uint16_t dlv = (115200ULL / rate);
    uart_8250_write_reg(u8250, UART_8250_DLL, (uint8_t)dlv);
    uart_8250_write_reg(u8250, UART_8250_DLM, (uint8_t)(dlv>>8));
    return 0;
}
int
generic_8250_uart_get_baudrate(
        struct uart *uart,
        baud_t *out)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);

    uint16_t dlv =
         ((uint16_t)uart_8250_read_reg(u8250, UART_8250_DLM) << 8)
        | (uint16_t)uart_8250_read_reg(u8250, UART_8250_DLL);

    return (115200ULL / dlv);
}

int
generic_8250_uart_set_databits(
        struct uart *uart,
        uart_databits_t bits)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);
    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);

    lcr &= ~0b11;

    switch(bits) {
        case 5:
            break;
        case 6:
            lcr |= 0b01;
            break;
        case 7:
            lcr |= 0b10;
            break;
        case 8:
            lcr |= 0b11;
            break;
        default:
            return -EINVAL;
    }

    uart_8250_write_reg(u8250, UART_8250_LCR, lcr);
    return 0;
}
int
generic_8250_uart_get_databits(
        struct uart *uart,
        uart_databits_t *bits)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);
    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);

    switch(lcr & 0b11) {
        case 0b00: *bits = 5; break;
        case 0b01: *bits = 6; break;
        case 0b10: *bits = 7; break;
        case 0b11: *bits = 8; break;
    }
    return 0;
}

int
generic_8250_uart_set_stopbits(
        struct uart *uart,
        uart_stopbits_t bits)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);
    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);

    lcr &= ~0b100;

    if(bits == UART_STOP_BITS_1) {
        uart_8250_write_reg(u8250, UART_8250_LCR, lcr);
        return 0;
    }

    uart_databits_t databits;
    int res = uart_get_databits(uart, &databits);
    if(res) {
        return res;
    }

    if(bits <= 5) {
        if(bits == UART_STOP_BITS_1_5) { 
            lcr |= 0b100;
            uart_8250_write_reg(u8250, UART_8250_LCR, lcr);
            return 0;
        }
    } else {
        if(bits == UART_STOP_BITS_2) {
            lcr |= 0b100;
            uart_8250_write_reg(u8250, UART_8250_LCR, lcr);
            return 0;
        }
    }

    return -EINVAL;
}
int
generic_8250_uart_get_stopbits(
        struct uart *uart,
        uart_stopbits_t *bits)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);
    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);

    if(!(lcr & 0b100)) {
        *bits = UART_STOP_BITS_1;
        return 0;
    }

    uart_databits_t databits;
    int res = uart_get_databits(uart, &databits);
    if(res) {
        return res;
    }

    if(databits <= 5) {
        *bits = UART_STOP_BITS_1_5;
    } else {
        *bits = UART_STOP_BITS_2;
    }

    return 0;
}

int
generic_8250_uart_set_parity(
        struct uart *uart,
        uart_parity_t parity)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);
    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);

    lcr &= ~0b111000; // Clear the bits
    switch(parity) {
        case UART_PARITY_NONE:
            break;
        case UART_PARITY_ODD:
            lcr |= 0b001000;
            break;
        case UART_PARITY_EVEN:
            lcr |= 0b011000;
            break;
        case UART_PARITY_HIGH:
            lcr |= 0b101000;
            break;
        case UART_PARITY_LOW:
            lcr |= 0b111000;
            break;
        default:
            return -EINVAL;
    }
    uart_8250_write_reg(u8250, UART_8250_LCR, lcr);
    return 0;
}
int
generic_8250_uart_get_parity(
        struct uart *uart,
        uart_parity_t *parity)
{
    struct uart_8250 *u8250 =
        container_of(uart, struct uart_8250, uart);

    uint8_t lcr = uart_8250_read_reg(u8250, UART_8250_LCR);
    if((lcr & 0b1000) == 0) {
        *parity = UART_PARITY_NONE;
    } else {
        switch((lcr >> 3) & 0x7) {
            case 0b001:
                *parity = UART_PARITY_ODD;
                break;
            case 0b011:
                *parity = UART_PARITY_EVEN;
                break;
            case 0b101:
                *parity = UART_PARITY_HIGH;
                break;
            case 0b111:
                *parity = UART_PARITY_LOW;
                break;
            default:
                return -EINVAL;
        }
    }
    return 0;
}

struct uart_driver 
generic_8250_uart_driver = {
    .get_baudrate = generic_8250_uart_get_baudrate,
    .set_baudrate = generic_8250_uart_set_baudrate,
    .get_databits = generic_8250_uart_get_databits,
    .set_databits = generic_8250_uart_set_databits,
    .get_stopbits = generic_8250_uart_get_stopbits,
    .set_stopbits = generic_8250_uart_set_stopbits,
    .get_parity = generic_8250_uart_get_parity,
    .set_parity = generic_8250_uart_set_parity,
};

