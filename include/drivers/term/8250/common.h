#ifndef __KANAWHA__SERIAL_UART_8250_COMMON_H__
#define __KANAWHA__SERIAL_UART_8250_COMMON_H__

#include <kanawha/dev/term.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/ops.h>
#include <kanawha/uart.h>

typedef enum
{
    UART_8250_RBR,
    UART_8250_IER,
    UART_8250_IIR,
    UART_8250_LCR,
    UART_8250_MCR,
    UART_8250_LSR,
    UART_8250_MSR,
    UART_8250_SCR,
    UART_8250_THR,
    UART_8250_FCR,
    UART_8250_DLL,
    UART_8250_DLM,
} reg_8250_t;

#define UART_8250_READ_REG_SIG(RET, ARG, ...)                                  \
    RET(uint8_t)                                                               \
    ARG(reg_8250_t, reg)

#define UART_8250_WRITE_REG_SIG(RET, ARG, ...)                                 \
    RET(int)                                                                   \
    ARG(reg_8250_t, reg)                                                       \
    ARG(uint8_t, val)

#define UART_8250_IRQ_RECV_AVAIL (0b0001)
#define UART_8250_IRQ_XMIT_EMPTY (0b0010)
#define UART_8250_IRQ_RECV_STATUS (0b0100)
#define UART_8250_IRQ_MODEM_STATUS (0b1000)

#define UART_8250_SET_IRQS_ENABLED_SIG(RET, ARG, ...)                          \
    RET(int)                                                                   \
    ARG(int, irqs)

// Should round down to the nearest supported amount
#define UART_8250_SET_RECV_TRIGGER_SIG(RET, ARG, ...)                          \
    RET(int)                                                                   \
    ARG(size_t, amt)

#define UART_8250_OP_LIST(OP, ...)                                             \
    OP(read_reg, UART_8250_READ_REG_SIG, ##__VA_ARGS__)                        \
    OP(write_reg, UART_8250_WRITE_REG_SIG, ##__VA_ARGS__)                      \
    OP(set_irqs_enabled, UART_8250_SET_IRQS_ENABLED_SIG, ##__VA_ARGS__)        \
    OP(set_recv_trigger, UART_8250_SET_RECV_TRIGGER_SIG, ##__VA_ARGS__)

struct uart_8250;
struct uart_8250_ops
{
    DECLARE_OP_LIST_PTRS(UART_8250_OP_LIST, struct uart_8250 *)
};

struct uart_8250
{
    struct uart_8250_ops *ops;

    irq_t irq;
    struct irq_action *irq_action;

    struct uart uart;
    struct term_dev term_dev;
};

DEFINE_OP_LIST_WRAPPERS(UART_8250_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        uart_8250,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR)

#undef UART_8250_READ_REG_SIG
#undef UART_8250_WRITE_REG_SIG
#undef UART_8250_OP_LIST

// Keeps a reference to "name"
int
register_uart_8250(const char *name,
                   struct uart_8250 *uart_8250,
                   struct uart_8250_ops *ops,
                   struct term_driver *term_driver,
                   struct uart_driver *uart_driver,
                   irq_handler_f *irq_handler);

int
unregister_uart_8250(struct uart_8250 *uart_8250);

int
generic_8250_set_irqs_enabled(struct uart_8250 *uart, int irqs);

int
generic_8250_set_recv_trigger(struct uart_8250 *uart, size_t amount);

#endif
