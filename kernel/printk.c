
#include <stdarg.h>

#include <kanawha/attribute.h>
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

static int
vprintk_flush(struct vprintk_state *state);
static int
vprintk_putc(struct vprintk_state *state, char c);
static int
vprintk_print_pointer(struct vprintk_state *state, void *ptr);

static char printk_state_buffer[CONFIG_PRINTK_BUFFER_SIZE] = {0};
static struct vprintk_state printk_state = {0};

int
do_printk(const char *fmt, ...)
{
    int res;

    va_list args;
    va_start(args, fmt);

    printk_lock_acquire();
    res = vprintk(&printk_state, fmt, &args);
    printk_lock_release();

    va_end(args);
    return res;
}

int
do_vprintk(const char *fmt, va_list args)
{
    int res;

    printk_lock_acquire();
    res = vprintk(&printk_state, fmt, (va_list *)&args);
    printk_lock_release();

    return res;
}

static int
vprintk_flush(struct vprintk_state *state)
{
    int res;

    if(state->buffer_head == 0)
    {
        return 0;
    }

    res =
        (*state->print_buffer)(state->state, state->buffer_head, state->buffer);

    if(res == 0)
    {
        state->buffer_head = 0;
        return 0;
    }
    else
    {
        return res;
    }
}

static int
vprintk_putc(struct vprintk_state *state, char c)
{
    int res;

    if(state->buffer_head >= state->buffer_size)
    {
        res = vprintk_flush(state);
        if(res)
        {
            return res;
        }
    }

    DEBUG_ASSERT(KERNEL_ADDR(state));
    DEBUG_ASSERT(KERNEL_ADDR(state->buffer));
    state->buffer[state->buffer_head] = c;
    state->buffer_head += 1;
    return 0;
}

static int
vprintk_puts(struct vprintk_state *state, char *str)
{
    int res;
    if(!KERNEL_ADDR(str))
    {
        vprintk_puts(state, "<ERROR-NON-KERNEL-STRING(");
        vprintk_print_pointer(state, str);
        vprintk_puts(state, ")>");
        return 0;
    }
    while(*str)
    {
        res = vprintk_putc(state, *str);
        if(res)
        {
            return res;
        }
        str++;
    }
    return 0;
}

static void
vprintk_reset_escaped_state(struct vprintk_state *state)
{
    state->uppercase_hex = 0;
    state->size_modifier = 0;
    state->leading_zeros = 0;
    state->digits_specifier = -1;
}

static inline char
vprintk_hex_char(struct vprintk_state *state, uint8_t val)
{
    if(val < 10)
    {
        return '0' + val;
    }
    else if(val < 16)
    {
        if(state->uppercase_hex)
        {
            return ('A' - 10) + val;
        }
        else
        {
            return ('a' - 10) + val;
        }
    }
    else
    {
        return '?';
    }
}

static int
vprintk_print_pointer(struct vprintk_state *state, void *ptr)
{
    int res;
    if(ptr == NULL)
    {
        return vprintk_puts(state, "(null)");
    }

    res = vprintk_puts(state, "0x");
    if(res)
    {
        return res;
    }

    uintptr_t val = (uintptr_t)ptr;

    for(size_t i = sizeof(uintptr_t) - 1; i >= 0; i--)
    {
        uint8_t byte = (val >> (8 * i)) & 0xFF;
        char msn = vprintk_hex_char(state, (byte >> 4) & 0xF);
        char lsn = vprintk_hex_char(state, (byte) & 0xF);

        res = vprintk_putc(state, msn);
        if(res)
        {
            return res;
        }

        res = vprintk_putc(state, lsn);
        if(res)
        {
            return res;
        }

        if(i == 0)
        {
            break;
        }
    }

    return 0;
}

static int
__vprintk_get_signed_number(struct vprintk_state *state,
                            unsigned long long *abs,
                            int *is_neg)
{
    union
    {
        int _int;
        long _long;
        long long _long_long;
    } value;

    long long val;

    switch(state->size_modifier)
    {
    case 0:
        value._int = va_arg(*state->args_ptr, int);
        val = value._int;
        break;
    case 1:
        value._long = va_arg(*state->args_ptr, long);
        val = value._long;
        break;
    case 2:
        value._long_long = va_arg(*state->args_ptr, long long);
        val = value._long_long;
        break;
    default:
        return -EINVAL;
    }

    *is_neg = val < 0;

    unsigned long long _abs;
    _abs = (unsigned long long)val;
    if(val > 0 || _abs == 1ULL << ((sizeof(unsigned long long) * 8) - 1))
    {
        // Don't need to convert (already positive or LONG_LONG_MIN)
    }
    else
    {
        _abs = -val;
    }

    *abs = _abs;

    return 0;
}

static int
__vprintk_get_unsigned_number(struct vprintk_state *state,
                              unsigned long long *val)
{
    union
    {
        unsigned int _int;
        unsigned long _long;
        unsigned long long _long_long;
    } value;

    switch(state->size_modifier)
    {
    case 0:
        value._int = va_arg(*state->args_ptr, unsigned int);
        *val = value._int;
        break;
    case 1:
        value._long = va_arg(*state->args_ptr, unsigned long);
        *val = value._long;
        break;
    case 2:
        value._long_long = va_arg(*state->args_ptr, unsigned long long);
        *val = value._long_long;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int
__vprintk_print_decimal(struct vprintk_state *state,
                        unsigned long long abs,
                        int is_neg)
{
    if(is_neg)
    {
        vprintk_putc(state, '-');
    }

    // Conservative estimate of the number of decimal digits needed (really is
    // the number of octal digits)
    size_t binary_digits_needed;
    if(abs != 0)
    {
        binary_digits_needed =
            (sizeof(unsigned long long) * 8) - __builtin_clzll(abs);
    }
    else
    {
        binary_digits_needed = 1;
    }
    size_t buffer_size = (binary_digits_needed / 3) + 1;

    size_t digits = 0;
    char buffer[buffer_size];
    do
    {
        char digit = '0' + (abs % 10);
        abs /= 10;
        if(digits < buffer_size)
        {
            buffer[digits] = digit;
            digits++;
        }
        else
        {
            return -EINVAL;
        }
    } while(abs != 0);

    if(digits <= 0)
    {
        return -EINVAL;
    }

    for(size_t i = digits - 1; i > 0; i--)
    {
        vprintk_putc(state, buffer[i]);
    }
    // Print the final digit
    vprintk_putc(state, buffer[0]);

    return 0;
}

static int
__vprintk_print_hexadecimal(struct vprintk_state *state,
                            unsigned long long abs,
                            int is_neg)
{
    if(is_neg)
    {
        vprintk_putc(state, '-');
    }

    size_t binary_digits_needed;
    if(abs != 0)
    {
        binary_digits_needed =
            (sizeof(unsigned long long) * 8) - __builtin_clzll(abs);
    }
    else
    {
        binary_digits_needed = 1;
    }
    size_t buffer_size = (binary_digits_needed / 4) + 1;

    size_t digits = 0;
    char buffer[buffer_size];
    do
    {
        char digit = vprintk_hex_char(state, abs & 0xF);
        abs >>= 4;
        if(digits < buffer_size)
        {
            buffer[digits] = digit;
            digits++;
        }
        else
        {
            return -EINVAL;
        }
    } while(abs != 0);

    if(digits <= 0)
    {
        return -EINVAL;
    }

    for(size_t i = digits - 1; i > 0; i--)
    {
        vprintk_putc(state, buffer[i]);
    }
    // Print the final digit
    vprintk_putc(state, buffer[0]);

    return 0;
}

static int
vprintk_print_signed_decimal(struct vprintk_state *state)
{
    int res;
    unsigned long long abs;
    int neg;

    res = __vprintk_get_signed_number(state, &abs, &neg);
    if(res)
    {
        return res;
    }

    res = __vprintk_print_decimal(state, abs, neg);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
vprintk_print_unsigned_decimal(struct vprintk_state *state)
{
    int res;
    unsigned long long val;

    res = __vprintk_get_unsigned_number(state, &val);
    if(res)
    {
        return res;
    }

    res = __vprintk_print_decimal(state, val, 0);
    if(res)
    {
        return res;
    }
    return 0;
}

static int
vprintk_print_unsigned_hexadecimal(struct vprintk_state *state)
{
    int res;
    unsigned long long val;

    res = __vprintk_get_unsigned_number(state, &val);
    if(res)
    {
        return res;
    }

    res = __vprintk_print_hexadecimal(state, val, 0);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
vprintk_print_errno(struct vprintk_state *state)
{
    int res;
    unsigned long long val;
    int is_neg;

    res = __vprintk_get_signed_number(state, &val, &is_neg);
    if(res)
    {
        return res;
    }

    int errno = (is_neg ? -1 : 1) * (int)val;


    res = vprintk_puts(state, (char*)errnostr(errno));
    if(res)
    {
        return res;
    }

    return 0;
}

static int
vprintk_print_thread_id(struct vprintk_state *state)
{
    int res;
    struct thread_state *thread = current_thread();
    if(thread == NULL) {
        vprintk_puts(state, "none");
        return 0;
    }
    thread_id_t tid = thread->id;
    res = __vprintk_print_decimal(state, (int)tid, 0);
    if(res) {
        return res;
    }
    return 0;
}

static int
vprintk_print_process_id(struct vprintk_state *state)
{
    int res;
    struct process *process = current_process();
    if(process == NULL) {
        vprintk_puts(state, "none");
        return 0;
    }
    res = __vprintk_print_decimal(state, (int)process->id, 0);
    if(res) {
        return res;
    }
    return 0; 
}

static int
vprintk_print_timestamp(struct vprintk_state *state)
{
    int res;
    time_t time = va_arg(*state->args_ptr, time_t);

    unsigned long seconds = time_to_sec(time);
    unsigned long nsec = time_to_nsec(time);
    nsec -= (seconds * 1000000000UL);

    res = __vprintk_print_decimal(state, seconds, 0);
    if(res)
    {
        return res;
    }

    res = vprintk_putc(state, '.');
    if(res) {
        return res;
    }
    char buffer[9];
    int seen_non_zero = 0;
    for(int i = sizeof(buffer)-1; i >= 0; i--) {
        int digit = '0' + (nsec % 10);
        nsec /= 10;
        if(digit == '0' && !seen_non_zero && i > 0) {
            buffer[i] = '\0';
        } else {
            buffer[i] = digit;
            seen_non_zero = 1;
        }
    }
    for(int i = 0; i <= sizeof(buffer); i++) {
        if(buffer[i] == '\0') {
            break;
        }
        res = vprintk_putc(state, buffer[i]);
        if(res) {
            return res;
        }
    }
    return 0;
}
static int
vprintk_handle_escaped(struct vprintk_state *state)
{
    int res = -1;

    vprintk_reset_escaped_state(state);

    // scratch variables
    void *ptr;
    char character;

    while(*(state->fmt_iter) && state->escaped)
    {
        char c = *(state->fmt_iter);
        state->fmt_iter++;

        switch(c)
        {

        case '%':
            res = vprintk_putc(state, c);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'c':
            character = va_arg(*state->args_ptr, int);
            res = vprintk_putc(state, character);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'l':
            state->size_modifier++;
            break;

        case '0':
            state->leading_zeros = 1;
            break;

        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            // TODO parse decimal number of digits
            return -EUNIMPL;

        case 'p':
            ptr = va_arg(*state->args_ptr, void *);
            state->uppercase_hex = 1;
            res = vprintk_print_pointer(state, ptr);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'd':
            res = vprintk_print_signed_decimal(state);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'u':
            res = vprintk_print_unsigned_decimal(state);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'x':
            res = vprintk_print_unsigned_hexadecimal(state);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 's':
            ptr = (void *)va_arg(*state->args_ptr, const char *);
            res = vprintk_puts(state, ptr);
            if(res)
            {
                return res;
            }
            state->escaped = 0;
            return 0;

        case 'e':
           res = vprintk_print_errno(state);
           if(res) {
               return res;
           }
           state->escaped = 0;
           return 0;

        case 'T':
           res = vprintk_print_thread_id(state);
           if(res) {
               return res;
           }
           state->escaped = 0;
           return 0;

        case 'P':
           res = vprintk_print_process_id(state);
           if(res) {
               return res;
           }
           state->escaped = 0;
           return 0;

        case 't':
           res = vprintk_print_timestamp(state);
           if(res) {
               return res;
           }
           state->escaped = 0;
           return 0;

        default:
            res = -1;
            return res;
        }
    }

    return res;
}

int
vprintk(struct vprintk_state *state, const char *fmt, va_list *args)
{
    int res;

    state->fmt_iter = fmt;
    state->args_ptr = args;
    state->escaped = 0;
    state->buffer_head = 0;

    while(*(state->fmt_iter))
    {
        char c = *(state->fmt_iter);
        state->fmt_iter++;

        if(c == '%')
        {
            state->escaped = 1;
            res = vprintk_handle_escaped(state);
        }
        else
        {
            res = vprintk_putc(state, c);
        }

        if(res)
        {
            return res;
        }
    }

    // Flush any remaining characters in the buffer
    res = vprintk_flush(state);
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
printk_print_buffer(void *state, size_t len, char *buffer)
{
    printk_handlers_lock_acquire();
    for(size_t i = 0; i < len; i++)
    {
        char c = buffer[i];

        for(size_t handler_i = 0; handler_i < CONFIG_PRINTK_MAX_HANDLERS;
            handler_i++)
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

int
printk_init(void)
{
    printk_state.buffer = printk_state_buffer;
    printk_state.buffer_size = CONFIG_PRINTK_BUFFER_SIZE;
    printk_state.print_buffer = printk_print_buffer;
    printk_state.state = NULL;

    printk_add_handler(klog_putc);
    return 0;
}

struct snprintk_state
{
    char *buf;
    size_t chars_left;
    size_t chars_attempted;
    struct vprintk_state vprintk_state;
};

static int
snprintk_print_buffer(void *_state, size_t n, char *buf)
{
    struct snprintk_state *state = _state;

    size_t to_copy = n > state->chars_left ? state->chars_left : n;
    memcpy(state->buf, buf, to_copy);

    state->chars_left -= to_copy;
    state->buf += to_copy;

    state->chars_attempted += n;

    return 0;
}

int
snprintk(char *buf, size_t size, const char *fmt, ...)
{
    struct snprintk_state state;

    state.chars_attempted = 0;
    state.chars_left = size - 1;
    state.buf = buf;

    char buffer[64];
    state.vprintk_state.buffer = buffer;
    state.vprintk_state.buffer_head = 0;
    state.vprintk_state.buffer_size = 64;
    state.vprintk_state.print_buffer = snprintk_print_buffer;

    state.vprintk_state.state = &state;

    va_list args;
    va_start(args, fmt);

    vprintk(&state.vprintk_state, fmt, &args);

    va_end(args);

    if(state.chars_left > 0)
    {
        *(char *)state.buf = '\0';
    }

    return state.chars_attempted;
}

EXPORT_SYMBOL(do_printk);
EXPORT_SYMBOL(printk_add_handler);
EXPORT_SYMBOL(snprintk);
