
#include <kanawha/fmt.h>
#include <kanawha/printer.h>
#include <kanawha/thread.h>
#include <kanawha/proc/process.h>
#include <kanawha/time.h>

char
fmt_digit(
        unsigned int digit,
        unsigned long flags)
{
    if(digit < 10) {
        return '0' + digit;
    }
    if(digit < 36) {
        char alpha_base = flags & FMT_FLAG_UPPERCASE ? 'A' : 'a';
        return alpha_base + (digit - 10);
    }
    return '?';
}
char
fmt_digit_uppercase(
        unsigned int digit)
{
    if(digit < 10) {
        return '0' + digit;
    }
    if(digit < 36) {
        return 'A' + (digit - 10);
    }
    return '?';
}

int
fmt_print_pointer(
        struct printer *printer,
        void * ptr,
        unsigned long flags)
{
    int res;
    if(ptr == NULL)
    {
        return printer_puts(printer, "(null)");
    }

    res = printer_puts(printer, "0x");
    if(res)
    {
        return res;
    }

    uintptr_t val = (uintptr_t)ptr;

    for(size_t i = sizeof(uintptr_t) - 1; i >= 0; i--)
    {
        uint8_t byte = (val >> (8 * i)) & 0xFF;
        char s[2];
        s[0] = fmt_digit((byte >> 4) & 0xF, flags);
        s[1] = fmt_digit((byte) & 0xF, flags);

        res = printer_write(printer, 2, s);
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

int
fmt_print_signed(
        struct printer *printer,
        long value,
        int base,
        unsigned long flags)
{
    int res;
    unsigned long uvalue;
    if(value < 0) {
        res = printer_putc(printer, '-');
        if(res) {
            return res;
        }
        uvalue = -value;
    } else {
        uvalue = value;
    }
    return fmt_print_unsigned(
            printer,
            uvalue,
            base,
            flags);
}
int
fmt_print_unsigned(
        struct printer *printer,
        unsigned long value,
        int base,
        unsigned long flags)
{
    int res;

    if(value == 0) {
        return printer_putc(printer, '0');
    }

    size_t binary_digits_needed = 8*sizeof(unsigned long);
    size_t buffer_size = binary_digits_needed;

    ssize_t digits = 0;
    char buffer[buffer_size];
    do
    {
        char digit = fmt_digit(value % base, flags);
        value /= base;
        if(digits < buffer_size)
        {
            buffer[digits] = digit;
            digits++;
        }
        else
        {
            return -EINVAL;
        }
    } while(value != 0);

    if(digits <= 0)
    {
        return -EINVAL;
    }

    for(ssize_t i = digits - 1; i >= 0; i--)
    {
        res = printer_putc(printer, buffer[i]);
        if(res) {
            return res;
        }
    }

    return 0;
}

int
fmt_print(
        struct printer *printer,
        const char *fmt,
        ...)
{
    int res;
    va_list args;
    va_start(args, fmt);
    res = fmt_vprint(printer, fmt, &args);
    va_end(args);
    return res;
}

int
fmt_vprint(
        struct printer *printer,
        const char *fmt,
        va_list *args)
{
    int res;

    unsigned int escaped = 0;
    unsigned int size_modifier = 0;

    char c;
    while((c = *fmt++)) {

        if(!escaped) {
            if(c == '%') {
                escaped = 1;
                continue;
            }
            res = printer_putc(printer, c);
            if(res) {
                return res;
            }
            continue;
        }

        // We are escaped right now
        switch(c) {
            // Modifiers
            case 'l':
                size_modifier++;
                continue; // Stay escaped

            // Specifiers
            case '%': {
                res = printer_putc(printer, '%');
                if(res) {
                    return res;
                }
                break;
            }
            case 'p': {
                void *ptr = va_arg(*args, void*);
                res = fmt_print_pointer(printer, ptr, 0);
                if(res) {
                    return res;
                }
                break;
            }
            case 'd':
            {
                long value;
                switch(size_modifier) {
                    case 0: value = va_arg(*args, int); break;
                    case 1: value = va_arg(*args, long); break;
                    case 2: value = va_arg(*args, long long); break;
                    default: return -EINVAL;
                }
                int base = 10;
                unsigned long flags = 0;
                res = fmt_print_signed(printer, value, base, flags);
                if(res) {
                    return res;
                }
                break;
            }
            case 'u':
            case 'x':
            {
                unsigned long value;
                switch(size_modifier) {
                    case 0: value = va_arg(*args, int); break;
                    case 1: value = va_arg(*args, long); break;
                    case 2: value = va_arg(*args, long long); break;
                    default: return -EINVAL;
                }
                int base;
                switch(c) {
                    case 'x':
                        base = 16;
                        break;
                    default:
                    case 'u':
                        base = 10;
                        break;
                }
                unsigned long flags = 0;
                res = fmt_print_unsigned(printer, value, base, flags);
                if(res) {
                    return res;
                }
                break;
            }
            case 's':
            {
                const char *str = va_arg(*args, const char *);
                res = printer_puts(printer, str);
                if(res) {
                    return res;
                }
                break;
            }
            case 'e':
            {
                int errno = va_arg(*args, int);
                res = printer_puts(printer, errnostr(errno));
                if(res) {
                    return res;
                }
                break;
            }
            case 'T':
            {
                struct thread_state *thread = current_thread();
                if(thread == NULL) {
                    res = printer_puts(printer, "none");
                    if(res) {
                        return res;
                    }
                    break;
                }
                thread_id_t tid = thread->id;
                res = fmt_print_unsigned(printer, tid, 10, 0);
                if(res) {
                    return res;
                }
                break;
            }
            case 'P':
            {
                struct process *process = current_process();
                if(process == NULL) {
                    res = printer_puts(printer, "none");
                    if(res) {
                        return res;
                    }
                    break;
                }
                res = fmt_print_unsigned(printer, (unsigned long)process->id, 10, 0);
                if(res) {
                    return res;
                }
                #ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
                if(process->tracked_exec) {
                    res = printer_putc(printer, '[');
                    if(res) {return res;}
                    res = printer_puts(printer, (char*)process->tracked_exec);
                    if(res) {return res;}
                    res = printer_putc(printer, ']');
                    if(res) {return res;}
                }
                #endif
                break;
            }
            case 't':
            {
                time_t time = va_arg(*args, time_t);
                unsigned long s = time_to_msec(time);
                res = fmt_print_unsigned(printer, s/1000, 10, 0);
                if(res) {
                    return res;
                }
                res = printer_puts(printer, ".");
                if(res) {
                    return res;
                }
                s = s % 1000;
                res = fmt_print_unsigned(printer, (s/100), 10, 0);
                if(res) {
                    return res;
                }
                s = s % 100;
                res = fmt_print_unsigned(printer, (s/10), 10, 0);
                if(res) {
                    return res;
                }
                s = s % 10;
                res = fmt_print_unsigned(printer, s, 10, 0);
                if(res) {
                    return res;
                }
                break;
            }
            default: {
                return -EINVAL;
            }
        }

        // Reset escaped
        escaped = 0;
        size_modifier = 0;
    }

    return 0;
}



