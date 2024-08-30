#ifndef __KANAWHA__UART_H__
#define __KANAWHA__UART_H__

#include <kanawha/ops.h>

typedef size_t baud_t;

typedef unsigned uart_databits_t;

typedef enum uart_stopbits {
    UART_STOP_BITS_1,
    UART_STOP_BITS_1_5,
    UART_STOP_BITS_2,
} uart_stopbits_t;

typedef enum uart_parity {
    UART_PARITY_NONE,
    UART_PARITY_ODD,
    UART_PARITY_EVEN,
    UART_PARITY_LOW,
    UART_PARITY_HIGH,
} uart_parity_t;

#define UART_SET_BAUDRATE_SIG(RET,ARG)\
RET(int)\
ARG(baud_t, rate)

#define UART_GET_BAUDRATE_SIG(RET,ARG)\
RET(int)\
ARG(baud_t *, baud)

#define UART_SET_DATABITS_SIG(RET,ARG)\
RET(int)\
ARG(uart_databits_t, bits)

#define UART_GET_DATABITS_SIG(RET,ARG)\
RET(int)\
ARG(uart_databits_t *, bits)

#define UART_SET_STOPBITS_SIG(RET,ARG)\
RET(int)\
ARG(uart_stopbits_t, bits)

#define UART_GET_STOPBITS_SIG(RET,ARG)\
RET(int)\
ARG(uart_stopbits_t *, bits)

#define UART_SET_PARITY_SIG(RET,ARG)\
RET(int)\
ARG(uart_parity_t, parity)

#define UART_GET_PARITY_SIG(RET,ARG)\
RET(int)\
ARG(uart_parity_t *, parity)

#define UART_OP_LIST(OP, ...)\
OP(set_baudrate, UART_SET_BAUDRATE_SIG, ##__VA_ARGS__)\
OP(get_baudrate, UART_GET_BAUDRATE_SIG, ##__VA_ARGS__)\
OP(set_databits, UART_SET_DATABITS_SIG, ##__VA_ARGS__)\
OP(get_databits, UART_GET_DATABITS_SIG, ##__VA_ARGS__)\
OP(set_stopbits, UART_SET_STOPBITS_SIG, ##__VA_ARGS__)\
OP(get_stopbits, UART_GET_STOPBITS_SIG, ##__VA_ARGS__)\
OP(set_parity, UART_SET_PARITY_SIG, ##__VA_ARGS__)\
OP(get_parity, UART_GET_PARITY_SIG, ##__VA_ARGS__)

struct uart;
struct uart_driver {
DECLARE_OP_LIST_PTRS(UART_OP_LIST, struct uart *)
};

struct uart {
    struct uart_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        UART_OP_LIST,
        static inline,
        /* No Prefix */,
        uart,
        ->driver->,
        SELF_ACCESSOR)

#undef UART_SET_BAUDRATE_SIG
#undef UART_GET_BAUDRATE_SIG
#undef UART_SET_DATABITS_SIG
#undef UART_GET_DATABITS_SIG
#undef UART_SET_STOPBITS_SIG
#undef UART_GET_STOPBITS_SIG
#undef UART_SET_PARITY_SIG
#undef UART_GET_PARITY_SIG
#undef UART_OP_LIST

#endif
