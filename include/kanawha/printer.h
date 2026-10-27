#ifndef __KANAWHA__PRINTER_H__
#define __KANAWHA__PRINTER_H__

#include <stdarg.h>
#include <kanawha/types.h>
#include <kanawha/ops.h>

#define PRINTER_PUTC_SIG(RET,ARG,...)\
    RET(int)\
    ARG(char, c)

#define PRINTER_PUTS_SIG(RET,ARG,...)\
    RET(int)\
    ARG(const char *, str)

#define PRINTER_WRITE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(size_t, buflen)\
    ARG(const char *, buffer)

#define PRINTER_OP_LIST(OP,...)\
OP(putc, PRINTER_PUTC_SIG, ##__VA_ARGS__)\
OP(puts, PRINTER_PUTS_SIG, ##__VA_ARGS__)\
OP(write, PRINTER_WRITE_SIG, ##__VA_ARGS__)\

struct printer;

struct printer {
    DECLARE_OP_LIST_PTRS(PRINTER_OP_LIST, struct printer *)
};

DEFINE_OP_LIST_WRAPPERS(PRINTER_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        printer,
                        INLINE_OPS_ACCESSOR,
                        SELF_ACCESSOR);

int
printer_putc_using_write(
        struct printer *printer,
        char c);
int
printer_puts_using_putc(
        struct printer *printer,
        const char *str);
int
printer_puts_using_write(
        struct printer *printer,
        const char *c);
int
printer_write_using_putc(
        struct printer *printer,
        size_t buflen,
        const char *buffer);

#endif
