#ifndef __KANAWHA__UART_8250_TERM_DEV_H__
#define __KANAWHA__UART_8250_TERM_DEV_H__

#include <kanawha/dev/term.h>
#include <kanawha/irq_domain.h>

int
generic_8250_term_dev_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action);

int
generic_8250_term_dev_putc(
        struct term_dev *term_dev,
        char c);

int
generic_8250_term_dev_flush(
        struct term_dev *term_dev);

int
generic_8250_term_dev_get_baudrate(
        struct term_dev *term_dev,
	baud_t *baud);

int
generic_8250_term_dev_set_baudrate(
        struct term_dev *term_dev,
	baud_t baud);

extern struct term_driver generic_8250_term_driver;

#endif
