#ifndef __KANAWHA__SERIAL_UART_8250_COMMON_H__
#define __KANAWHA__SERIAL_UART_8250_COMMON_H__

#include <kanawha/char_dev.h>
#include <kanawha/uart.h>
#include <kanawha/ops.h>

typedef enum {
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

#define UART_8250_READ_REG_SIG(RET,ARG)\
RET(uint8_t)\
ARG(reg_8250_t, reg)

#define UART_8250_WRITE_REG_SIG(RET,ARG)\
RET(void)\
ARG(reg_8250_t, reg)\
ARG(uint8_t, val)

#define UART_8250_OP_LIST(OP, ...)\
OP(read_reg, UART_8250_READ_REG_SIG, ##__VA_ARGS__)\
OP(write_reg, UART_8250_WRITE_REG_SIG, ##__VA_ARGS__)

struct uart_8250;
struct uart_8250_ops
{
DECLARE_OP_LIST_PTRS(UART_8250_OP_LIST, struct uart_8250 *)
};

struct uart_8250
{
    struct uart_8250_ops *ops;

    struct uart uart;
    struct char_dev char_dev;
};

DEFINE_OP_LIST_WRAPPERS(
        UART_8250_OP_LIST,
        static inline,
        /* No Prefix */,
        uart_8250,
        ->ops->,
        SELF_ACCESSOR)

#undef UART_8250_READ_REG_SIG
#undef UART_8250_WRITE_REG_SIG
#undef UART_8250_OP_LIST

#endif
