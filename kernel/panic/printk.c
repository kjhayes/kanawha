
#include <kanawha/export.h>
#include <kanawha/panic.h>
#include <kanawha/printk.h>
#include <stdarg.h>

static char panic_state_buffer[CONFIG_PANIC_BUFFER_SIZE] = {0};
static struct vprintk_state panic_state = {0};

int
do_panic_printk(const char *fmt, ...)
{
    int res;

    va_list args;
    va_start(args, fmt);

    res = vprintk(&panic_state, fmt, &args);

    va_end(args);
    return res;
}

int
panic_printk_init(void)
{
    panic_state.buffer = panic_state_buffer;
    panic_state.buffer_size = CONFIG_PANIC_BUFFER_SIZE;
    panic_state.print_buffer = printk_print_buffer;
    panic_state.state = NULL;
    return 0;
}

EXPORT_SYMBOL(do_panic_printk);
