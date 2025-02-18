
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

struct doprnt_state {
    // Inputs
    const char *fmt_iter;
    va_list *args_ptr;

    // State
    int escaped;

    int uppercase_hex;
    int size_modifier;
    int leading_zeros;
    int digits_specifier;
    int width;
    int dot;
    int precision;

    int num_printed;
    
    // Constants
    void *priv_state;
    int(*putchar)(int c, void *state);
};

static void
doprnt_reset_escaped_state(struct doprnt_state *state) 
{
    state->uppercase_hex = 0;
    state->size_modifier = 0;
    state->leading_zeros = 0;
    state->width = -1;
    state->dot = 0;
    state->precision = -1;
    state->digits_specifier = -1;
}

void
doprnt_putc(struct doprnt_state *state, char c) {
    state->num_printed++;
    (state->putchar)(c, state->priv_state);
}

static void
doprnt_puts(struct doprnt_state *state, const char *str) {
    while(*str) {
        doprnt_putc(state, *str);
        str++;
    }
}

static inline char
doprnt_hex_char(struct doprnt_state *state, uint8_t val) {
    if(val < 10) {
        return '0' + val;
    } else if (val < 16) {
        if(state->uppercase_hex) {
            return ('A'-10) + val;
        } else {
            return ('a'-10) + val;
        }
    } else {
        return '?';
    }
}

static void
doprnt_print_pointer(struct doprnt_state *state, void *ptr) 
{
    if(ptr == NULL) {
        doprnt_puts(state, "(null)");
        return;
    }

    doprnt_puts(state, "0x");

    uintptr_t val = (uintptr_t)ptr;

    for(size_t i = sizeof(uintptr_t)-1; i >= 0; i--) {
        uint8_t byte = (val >> (8*i)) & 0xFF;
        char msn = doprnt_hex_char(state, (byte >> 4) & 0xF);
        char lsn = doprnt_hex_char(state, (byte) & 0xF);

        doprnt_putc(state, msn);        
        doprnt_putc(state, lsn);

        if(i == 0) {
            break;
        }
    }
}

static void
__doprnt_get_signed_number(struct doprnt_state *state, unsigned long long *abs, int *is_neg) 
{
    union {
        int _int;
        long _long;
        long long _long_long;
    } value;

    long long val;

    switch(state->size_modifier) {
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
            return;
    }

    *is_neg = val < 0;

    unsigned long long _abs;
    _abs = (unsigned long long)val;
    if(val > 0 || _abs == 1ULL<<((sizeof(unsigned long long)*8)-1)) {
        // Don't need to convert (already positive or LONG_LONG_MIN)
    } else {
        _abs = -val;
    }

    *abs = _abs;
}

static void
__doprnt_get_unsigned_number(struct doprnt_state *state, unsigned long long *val)
{
    union {
        unsigned int _int;
        unsigned long _long;
        unsigned long long _long_long;
    } value;

    switch(state->size_modifier) {
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
            return;
    }
}

static void
__doprnt_print_decimal(struct doprnt_state *state, unsigned long long abs, int is_neg) 
{
    if(is_neg) {
        doprnt_putc(state, '-');
    }
    
    // Conservative estimate of the number of decimal digits needed (really is the number of octal digits)
    size_t binary_digits_needed;
    if(abs != 0) {
        binary_digits_needed = (sizeof(unsigned long long)*8) - __builtin_clzll(abs);
    } else {
        binary_digits_needed = 1;
    }
    size_t buffer_size = (binary_digits_needed / 3) + 1;

    size_t digits = 0;
    char buffer[buffer_size];
    do {
        char digit = '0' + (abs % 10);
        abs /= 10;
        if(digits < buffer_size) {
            buffer[digits] = digit;
            digits++;
        } else {
            return;
        }
    } while(abs != 0);

    if(digits<=0) {
        return;
    }

    if((state->precision > 0) && (digits < (size_t)state->precision)) {
        for(size_t i = 0; i < ((size_t)state->precision - digits); i++) {
            doprnt_putc(state, '0');
        }
    }

    for(size_t i = digits-1; i > 0; i--) {
        doprnt_putc(state, buffer[i]);
    }
    // Print the final digit
    doprnt_putc(state, buffer[0]);
}

static void 
__doprnt_print_hexadecimal(struct doprnt_state *state, unsigned long long abs, int is_neg) 
{
    if(is_neg) {
        doprnt_putc(state, '-');
    }
    
    size_t binary_digits_needed;
    if(abs != 0) {
        binary_digits_needed = (sizeof(unsigned long long)*8) - __builtin_clzll(abs);
    } else {
        binary_digits_needed = 1;
    }
    size_t buffer_size = (binary_digits_needed / 4) + 1;

    size_t digits = 0;
    char buffer[buffer_size];
    do {
        char digit = doprnt_hex_char(state, abs & 0xF);
        abs >>= 4;
        if(digits < buffer_size) {
            buffer[digits] = digit;
            digits++;
        } else {
            return;
        }
    } while(abs != 0);

    if(digits<=0) {
        return;
    }

    if((state->precision > 0) && (digits < (size_t)state->precision)) {
        for(size_t i = 0; i < ((size_t)state->precision - digits); i++) {
            doprnt_putc(state, '0');
        }
    }

    for(size_t i = digits-1; i > 0; i--) {
        doprnt_putc(state, buffer[i]);
    }
    // Print the final digit
    doprnt_putc(state, buffer[0]);
}

static void
doprnt_print_signed_decimal(struct doprnt_state *state) 
{
    unsigned long long abs;
    int neg;

    __doprnt_get_signed_number(state, &abs, &neg);
    __doprnt_print_decimal(state, abs, neg);
}

static void
doprnt_print_unsigned_decimal(struct doprnt_state *state) 
{
    unsigned long long val;

    __doprnt_get_unsigned_number(state, &val);
    __doprnt_print_decimal(state, val, 0);
}

static void
doprnt_print_unsigned_hexadecimal(struct doprnt_state *state) 
{
    unsigned long long val;

    __doprnt_get_unsigned_number(state, &val);
    __doprnt_print_hexadecimal(state, val, 0);
}

static void
doprnt_handle_escaped(struct doprnt_state *state) {

    doprnt_reset_escaped_state(state);

    // scratch variables
    void *ptr;
    char character;

    while(*(state->fmt_iter) && state->escaped) {
        char c = *(state->fmt_iter);
        state->fmt_iter++;

        switch(c) {
            case '%':
                doprnt_putc(state, c);
                state->escaped = 0;
                return;
            case 'c':
                character = va_arg(*state->args_ptr, int);
                doprnt_putc(state, character);
                state->escaped = 0;
                return;
            case 'l':
                state->size_modifier++;
                break;

            case '0':
                state->leading_zeros = 1;
                break;

            case '.':
                state->dot = 1;
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
                // TODO handle two-digit values properly
                if(state->dot) {
                    state->precision = (c - '0');
                } else {
                    state->width = (c - '0');
                }
                break;

            case 'p':
                ptr = va_arg(*state->args_ptr, void*);
                state->uppercase_hex = 1;
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
                ptr = (void*)va_arg(*state->args_ptr, const char*);
                doprnt_puts(state, ptr);
                state->escaped = 0;
                return;
            default:
                return;
        }
    }
}

int
doprnt(
        int(*putchar)(int c, void *state),
        void *priv_state,
        const char *fmt,
        va_list *args)
{
    struct doprnt_state state = {
      .fmt_iter = fmt,
      .args_ptr = args,
      .escaped = 0,
      .num_printed = 0,
      .priv_state = priv_state,
      .putchar = putchar,
    };

    while(*(state.fmt_iter)) {
        char c = *(state.fmt_iter);
        state.fmt_iter++;

        if(c == '%') {
            state.escaped = 1;
            doprnt_handle_escaped(&state);
        } else {
            doprnt_putc(&state, c);
        }
    }

    return state.num_printed;
}

