
#include <kanawha/printer.h>
#include <kanawha/string.h>

int
printer_putc_using_write(
        struct printer *printer,
        char c)
{
    return printer_write(printer, 1, &c);
}
int
printer_puts_using_putc(
        struct printer *printer,
        const char *str)
{
    int res;
    char c;
    while((c = *str++)) {
        res = printer_putc(printer, c);
        if(res) {
            return res;
        }
    }
    return 0;
}
int
printer_puts_using_write(
        struct printer *printer,
        const char *str)
{
    size_t len = strlen(str);
    return printer_write(printer, len, str);
}
int
printer_write_using_putc(
        struct printer *printer,
        size_t buflen,
        const char *buffer)
{
    int res;
    for(size_t i = 0; i < buflen; i++) {
        res = printer_putc(printer, buffer[i]);
        if(res < 0) {
            return res;
        }
    }
    return 0;
}

