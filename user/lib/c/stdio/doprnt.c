
#include <elk-libc-internal/doprnt.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct doprnt_state
{
    // Inputs
    const char *fmt_iter;
    va_list args;

    // State
    int escaped;

    int uppercase_digits;
    int size_modifier;
    int leading_zeros;
    int digits_specifier;
    int width;
    int dot;
    int star;
    int precision;

    int num_printed;

    // Constants
    void *priv_state;
    int (*putchar)(int c, void *state);
};

static void
doprnt_reset_escaped_state(struct doprnt_state *state)
{
    state->uppercase_digits = 0;
    state->size_modifier = 0;
    state->leading_zeros = 0;
    state->width = -1;
    state->dot = 0;
    state->star = 0;
    state->precision = -1;
    state->digits_specifier = -1;
}

void
doprnt_putc(struct doprnt_state *state, char c)
{
    state->num_printed++;
    (state->putchar)(c, state->priv_state);
}

static void
doprnt_puts(struct doprnt_state *state, const char *str)
{
    while(*str)
    {
        doprnt_putc(state, *str);
        str++;
    }
}

static inline char
doprnt_digit_char(struct doprnt_state *state, size_t digit_index)
{
    if(digit_index < 10)
    {
        return '0' + digit_index;
    }
    else if(digit_index < 36)
    {
        if(state->uppercase_digits)
        {
            return ('A' - 10) + digit_index;
        }
        else
        {
            return ('a' - 10) + digit_index;
        }
    }
    else
    {
        return '?';
    }
}

static void
doprnt_print_pointer(struct doprnt_state *state, void *ptr)
{
    if(ptr == NULL)
    {
        doprnt_puts(state, "(null)");
        return;
    }

    doprnt_puts(state, "0x");

    uintptr_t val = (uintptr_t)ptr;

    for(size_t i = sizeof(uintptr_t) - 1; i >= 0; i--)
    {
        uint8_t byte = (val >> (8 * i)) & 0xFF;
        char msn = doprnt_digit_char(state, (byte >> 4) & 0xF);
        char lsn = doprnt_digit_char(state, (byte) & 0xF);

        doprnt_putc(state, msn);
        doprnt_putc(state, lsn);

        if(i == 0)
        {
            break;
        }
    }
}

static void
__doprnt_get_signed_number(struct doprnt_state *state,
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
        value._int = va_arg(state->args, int);
        val = value._int;
        break;
    case 1:
        value._long = va_arg(state->args, long);
        val = value._long;
        break;
    case 2:
        value._long_long = va_arg(state->args, long long);
        val = value._long_long;
        break;
    default:
        return;
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
}

static void
__doprnt_get_unsigned_number(struct doprnt_state *state,
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
        value._int = va_arg(state->args, unsigned int);
        *val = value._int;
        break;
    case 1:
        value._long = va_arg(state->args, unsigned long);
        *val = value._long;
        break;
    case 2:
        value._long_long = va_arg(state->args, unsigned long long);
        *val = value._long_long;
        break;
    default:
        return;
    }
}

static void
__doprnt_print_number(struct doprnt_state *state,
                      unsigned long long abs,
                      int is_neg,
                      int base)
{
    if(abs == 0 && state->precision == 0)
    {
        // Print nothing
        return;
    }

    size_t digits_needed = 1;
    size_t power = base;
    if(abs != 0)
    {
        while(abs / power)
        {
            digits_needed++;
            power *= base;
        }
    }

    size_t precision_padding = 0;
    if(state->precision != -1 && (state->precision > digits_needed))
    {
        precision_padding = state->precision - (digits_needed);
    }

    size_t width_padding = 0;
    if(state->width != -1 &&
       (state->width > (precision_padding + digits_needed + (!!is_neg))))
    {
        width_padding =
            state->width - (precision_padding + digits_needed + (!!is_neg));
    }

    size_t buffer_size =
        width_padding + precision_padding + (!!is_neg) + digits_needed + 1;

    char buffer[buffer_size];

    memset(buffer, (state->leading_zeros ? '0' : ' '), width_padding);
    memset(buffer + width_padding, '0', precision_padding);

    size_t padding = precision_padding + width_padding;

    if(is_neg)
    {
        buffer[padding] = '-';
    }

    power = base;
    for(size_t i = buffer_size - 1; i > 0; i--)
    {
        size_t index = i - 1;

        size_t digit_index = (abs % base);
        char digit = doprnt_digit_char(state, digit_index);
        buffer[index] = digit;
        abs /= base;
        if(abs == 0)
        {
            break;
        }
    }

    buffer[buffer_size - 1] = '\0';

    doprnt_puts(state, buffer);
}

// static void
//__doprnt_print_decimal(struct doprnt_state *state, unsigned long long abs,
// int is_neg)
//{
//     size_t digits_needed = 1;
//     size_t power_of_ten = 10;
//     if(abs != 0) {
//         while(abs / power_of_ten) {
//             digits_needed++;
//             power_of_ten *= 10;
//         }
//     }
//
//     if(abs == 0 && state->precision == 0) {
//         // Print nothing
//         return;
//     }
//
//     size_t padding = 0;
//     if(state->precision != -1 && (state->precision >
//     (digits_needed+(!!is_neg)))) {
//         padding = state->precision - (digits_needed+(!!is_neg));
//     }
//
//     size_t buffer_size = padding+(!!is_neg)+digits_needed+1;
//
//     char buffer[buffer_size];
//
//     memset(buffer, (state->leading_zeros ? '0' : ' '), padding);
//
//     if(is_neg) {
//         buffer[padding] = '-';
//     }
//
//     power_of_ten = 10;
//     for(size_t i = buffer_size-1; i > 0; i--) {
//         size_t index = i-1;
//
//         char digit = '0' + (abs % 10);
//         buffer[index] = digit;
//         abs /= 10;
//         if(abs == 0) {
//             break;
//         }
//     }
//
//     buffer[buffer_size-1] = '\0';
//
//     doprnt_puts(state, buffer);
// }
//
// static void
//__doprnt_print_hexadecimal(struct doprnt_state *state, unsigned long long
// abs, int is_neg)
//{
//     if(is_neg) {
//         doprnt_putc(state, '-');
//     }
//
//     size_t binary_digits_needed;
//     if(abs != 0) {
//         binary_digits_needed = (sizeof(unsigned long long)*8) -
//         __builtin_clzll(abs);
//     } else {
//         binary_digits_needed = 1;
//     }
//     size_t buffer_size = (binary_digits_needed / 4) + 1;
//
//     size_t digits = 0;
//     char buffer[buffer_size];
//     do {
//         char digit = doprnt_digit_char(state, abs & 0xF);
//         abs >>= 4;
//         if(digits < buffer_size) {
//             buffer[digits] = digit;
//             digits++;
//         } else {
//             return;
//         }
//     } while(abs != 0);
//
//     if(digits<=0) {
//         return;
//     }
//
//     if((state->precision > 0) && (digits < (size_t)state->precision)) {
//         for(size_t i = 0; i < ((size_t)state->precision - digits); i++) {
//             doprnt_putc(state, '0');
//         }
//     }
//
//     for(size_t i = digits-1; i > 0; i--) {
//         doprnt_putc(state, buffer[i]);
//     }
//     // Print the final digit
//     doprnt_putc(state, buffer[0]);
// }

static void
doprnt_print_signed_decimal(struct doprnt_state *state)
{
    unsigned long long abs;
    int neg;

    __doprnt_get_signed_number(state, &abs, &neg);
    __doprnt_print_number(state, abs, neg, 10);
}

static void
doprnt_print_unsigned_decimal(struct doprnt_state *state)
{
    unsigned long long val;

    __doprnt_get_unsigned_number(state, &val);
    __doprnt_print_number(state, val, 0, 10);
}

static void
doprnt_print_unsigned_hexadecimal(struct doprnt_state *state)
{
    unsigned long long val;

    __doprnt_get_unsigned_number(state, &val);
    __doprnt_print_number(state, val, 0, 16);
}

static void
doprnt_handle_escaped(struct doprnt_state *state)
{

    doprnt_reset_escaped_state(state);

    // scratch variables
    void *ptr;
    char character;
    size_t tmp_len;

    while(*(state->fmt_iter) && state->escaped)
    {
        char c = *(state->fmt_iter);
        state->fmt_iter++;

        switch(c)
        {
        case '%':
            doprnt_putc(state, c);
            state->escaped = 0;
            return;
        case 'c':
            character = va_arg(state->args, int);
            doprnt_putc(state, character);
            state->escaped = 0;
            return;
        case 'l':
            state->size_modifier++;
            break;

        case '0':
            if(state->precision != -1)
            {
                state->precision *= 10;
            }
            else if(state->width != -1)
            {
                state->width *= 10;
            }
            else
            {
                state->leading_zeros = 1;
            }
            break;

        case '.':
            state->dot = 1;
            break;

        case '*':
            state->star = 1;
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
            if(state->dot)
            {
                if(state->precision == -1)
                {
                    state->precision = (c - '0');
                }
                else
                {
                    state->precision *= 10;
                    state->precision += (c - '0');
                }
            }
            else
            {
                if(state->width == -1)
                {
                    state->width = (c - '0');
                }
                else
                {
                    state->width *= 10;
                    state->width += (c - '0');
                }
            }
            break;

        case 'p':
            ptr = va_arg(state->args, void *);
            state->uppercase_digits = 1;
            doprnt_print_pointer(state, ptr);
            state->escaped = 0;
            return;

        case 'd':
        case 'i':
            doprnt_print_signed_decimal(state);
            state->escaped = 0;
            return;

        case 'u':
            doprnt_print_unsigned_decimal(state);
            state->escaped = 0;
            return;

        case 'x':
            doprnt_print_unsigned_hexadecimal(state);
            state->escaped = 0;
            return;

        case 's':
            if(state->star)
            {
                state->width = (int)va_arg(state->args, int);
            }
            ptr = (void *)va_arg(state->args, const char *);
            if(state->width == -1)
            {
                doprnt_puts(state, ptr);
            }
            else
            {
                tmp_len = strlen((char *)ptr);
                if(state->width > tmp_len)
                {
                    for(int i = 0; i < (state->width - tmp_len); i++)
                    {
                        doprnt_putc(state, ' ');
                    }
                }
                doprnt_puts(state, (char *)ptr);
            }
            state->escaped = 0;
            return;
        default:
            break;
        }
    }
}

int
doprnt(int (*putchar)(int c, void *state),
       void *priv_state,
       const char *fmt,
       va_list args)
{
    struct doprnt_state state = {
        .fmt_iter = fmt,
        .escaped = 0,
        .num_printed = 0,
        .priv_state = priv_state,
        .putchar = putchar,
    };
    va_copy(state.args, args);

    while(*(state.fmt_iter))
    {
        char c = *(state.fmt_iter);
        state.fmt_iter++;

        if(c == '%')
        {
            state.escaped = 1;
            doprnt_handle_escaped(&state);
        }
        else
        {
            doprnt_putc(&state, c);
        }
    }

    va_end(state.args);

    return state.num_printed;
}
