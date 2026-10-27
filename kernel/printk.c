
#include <stdarg.h>

#include <kanawha/attribute.h>
#include <kanawha/printer.h>
#include <kanawha/errno.h>
#include <kanawha/export.h>
#include <kanawha/irq.h>
#include <kanawha/klog.h>
#include <kanawha/lock.h>
#include <kanawha/printk.h>
#include <kanawha/proc/process.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/types.h>

DEFINE_LOCAL_IRQ_LOCK(printk_lock);

int
do_printk(const char *fmt, ...)
{
    int res;

    va_list args;
    va_start(args, fmt);

    printk_lock_acquire();
    res = fmt_vprint(printk_printer(), fmt, &args);
    printk_lock_release();

    va_end(args);

    return res;
}

/*
 * Early Printk
 */
DEFINE_LOCAL_IRQ_LOCK(printk_handlers_lock);
static printk_handler_f *(printk_handlers[CONFIG_PRINTK_MAX_HANDLERS]) = {NULL};

int
printk_add_handler(printk_handler_f *handler)
{
    printk_handlers_lock_acquire();
    for(size_t i = 0; i < CONFIG_PRINTK_MAX_HANDLERS; i++)
    {
        if(printk_handlers[i] == NULL)
        {
            printk_handlers[i] = handler;
            printk_handlers_lock_release();
            return 0;
        }
    }
    printk_handlers_lock_release();
    return -ENOMEM;
}

int
printk_remove_handler(printk_handler_f *handler)
{
    printk_handlers_lock_acquire();
    for(size_t i = 0; i < CONFIG_PRINTK_MAX_HANDLERS; i++)
    {
        if(printk_handlers[i] == handler)
        {
            printk_handlers[i] = NULL;
        }
    }
    printk_handlers_lock_release();
    return 0;
}

int
printk_init(void)
{
    printk_add_handler(klog_putc);
    return 0;
}

EXPORT_SYMBOL(do_printk);
EXPORT_SYMBOL(printk_add_handler);

// PANIC printing (unlocked)
int
do_panic_printk(const char *fmt, ...)
{
    int res;

    va_list args;
    va_start(args, fmt);

    res = fmt_vprint(printk_printer(), fmt, &args);

    va_end(args);
    return res;
}

EXPORT_SYMBOL(do_panic_printk);

// printk Printer
static int
printk_printer_putc(
        struct printer *p,
        char c)
{
    printk_handlers_lock_acquire();
    for(size_t handler_i = 0; handler_i < CONFIG_PRINTK_MAX_HANDLERS; handler_i++)
    {
        printk_handler_f *func = printk_handlers[handler_i];
        if(func != NULL)
        {
            (*func)(c);
        }
    }
    printk_handlers_lock_release();
    return 0;
}

static int
printk_printer_puts(
        struct printer *p,
        const char *str)
{
    printk_handlers_lock_acquire();
    char c;
    while((c = *str++)) {
        for(size_t handler_i = 0; handler_i < CONFIG_PRINTK_MAX_HANDLERS; handler_i++)
        {
            printk_handler_f *func = printk_handlers[handler_i];
            if(func != NULL)
            {
                (*func)(c);
            }
        }
    }
    printk_handlers_lock_release();
    return 0;
}
static int
printk_printer_write(
        struct printer *printer,
        size_t buflen,
        const char *buffer)
{
    printk_handlers_lock_acquire();
    for(size_t i = 0; i < buflen; i++)
    {
        char c = buffer[i];

        for(size_t handler_i = 0; handler_i < CONFIG_PRINTK_MAX_HANDLERS; handler_i++)
        {
            printk_handler_f *func = printk_handlers[handler_i];
            if(func != NULL)
            {
                (*func)(c);
            }
        }
    }
    printk_handlers_lock_release();

    return 0;
}

static struct printer 
_printk_printer = {
    .putc = printk_printer_putc,
    .puts = printk_printer_puts,
    .write = printk_printer_write,
};
struct printer *
printk_printer(void)
{
    return &_printk_printer;
}

