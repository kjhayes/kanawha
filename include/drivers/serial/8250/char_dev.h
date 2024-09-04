#ifndef __KANAWHA__UART_8250_CHAR_DEV_H__
#define __KANAWHA__UART_8250_CHAR_DEV_H__

#include <kanawha/char_dev.h>
#include <kanawha/irq_domain.h>

int
generic_8250_char_dev_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action);

size_t
generic_8250_char_dev_read(
        struct char_dev *char_dev,
        void *buffer,
        size_t amount);

size_t
generic_8250_char_dev_write(
        struct char_dev *char_dev,
        void *buffer,
        size_t amount);

int
generic_8250_char_dev_flush(
        struct char_dev *char_dev);

extern struct char_driver 
generic_8250_char_driver;

#endif
