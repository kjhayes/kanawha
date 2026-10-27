#ifndef __KANAWHA__FMT_H__
#define __KANAWHA__FMT_H__

#include <stdarg.h>
#include <kanawha/types.h>

struct printer;

#define FMT_FLAG_UPPERCASE (1UL<<0)

char
fmt_digit(
        unsigned int digit,
        unsigned long flags);

int
fmt_print_pointer(
        struct printer *printer,
        void * value,
        unsigned long flags);

int
fmt_print_signed(
        struct printer *printer,
        long value,
        int base,
        unsigned long flags);
int
fmt_print_unsigned(
        struct printer *printer,
        unsigned long value,
        int base,
        unsigned long flags);

// Formatted printing
int
fmt_vprint(
        struct printer *printer,
        const char *fmt,
        va_list *args);
int
fmt_print(
        struct printer *printer,
        const char *fmt,
        ...);

#endif
