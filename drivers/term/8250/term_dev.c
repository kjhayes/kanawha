
#include <kanawha/dev/term.h>
#include <kanawha/stddef.h>
#include <kanawha/irq_domain.h>
#include <drivers/term/8250/common.h>

int
generic_8250_term_dev_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    dprintk("generic_8250_term_dev_irq_handler!\n");
    struct uart_8250 *uart = action->handler_data.priv_data;

    uint8_t iir = uart_8250_read_reg(uart, UART_8250_IIR);
    if(iir & 0b1) {
	// No interrupt pending
	return IRQ_NONE;
    }

    char c;

    uint8_t reason = (iir>>1) & 0b111;

    switch(reason) {
	case 0b011: // LSR Change
	    (void)(volatile uint8_t)uart_8250_read_reg(uart, UART_8250_LSR);
	    break;
	case 0b010: // Recv Data Avail
	case 0b110: // Timeout
            c = uart_8250_read_reg(uart, UART_8250_RBR);
            term_driver_provide_input(&uart->term_dev, c);
	    break;
	case 0b000: // Modem Status Change
	    (void)(volatile uint8_t)uart_8250_read_reg(uart, UART_8250_MSR);
	    break;
	case 0b001: // X-mit Empty
	    term_driver_poke_output(&uart->term_dev);
	    break; // Cleared by reading IIR
    }

    return IRQ_NONE;
}

int
generic_8250_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    struct uart_8250 *uart =
        container_of(term_dev, struct uart_8250, term_dev);

    if((uart_8250_read_reg(uart, UART_8250_LSR) & 0x20) == 0) {
        return -EWOULDBLOCK;
    }
    uart_8250_write_reg(uart, UART_8250_THR, c);

    return 0;
}

int
generic_8250_term_dev_flush(
        struct term_dev *term_dev)
{
    struct uart_8250 *uart =
        container_of(term_dev, struct uart_8250, term_dev);
    return -EUNIMPL;
}

int
generic_8250_term_dev_get_baudrate(
        struct term_dev *term_dev,
	baud_t *baud)
{
    struct uart_8250 *uart =
        container_of(term_dev, struct uart_8250, term_dev);
    return uart_get_baudrate(&uart->uart, baud);
}

int
generic_8250_term_dev_set_baudrate(
        struct term_dev *term_dev,
	baud_t baud)
{
    struct uart_8250 *uart =
        container_of(term_dev, struct uart_8250, term_dev);
    return uart_set_baudrate(&uart->uart, baud);
}

struct term_driver 
generic_8250_term_driver = {
    .putc = generic_8250_term_dev_putc,
    .flush = generic_8250_term_dev_flush,
    .get_baudrate = generic_8250_term_dev_get_baudrate,
    .set_baudrate = generic_8250_term_dev_set_baudrate,
};

