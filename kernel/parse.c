
#include <kanawha/parse.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>

static void
determine_sign(
        const char **str_ptr,
        int *sign)
{
    switch((*str_ptr)[0]) {
        case '-':
            *str_ptr = *str_ptr + 1;
            *sign = -1;
            break;
        case '+':
            *str_ptr = *str_ptr + 1;
            *sign = 1;
            break;
        default:
            break;
    }
}

static void
determine_base(
        const char **str_ptr,
        int *base_ptr)
{
    if((*str_ptr)[0] == '0') {
        if((*str_ptr)[1] == 'x' ||
           (*str_ptr)[1] == 'X') {
            *base_ptr = 16;
            *str_ptr = *str_ptr + 2;
        } else {
            *base_ptr = 8;
            *str_ptr = *str_ptr + 1;
        }
    }
}

int
parse_int(
        const char *str,
        int def)
{
    int res;
    int sign = 1;
    determine_sign(&str, &sign);
    int base = 10;
    determine_base(&str, &base);
    unsigned int value;
    res = kstrtou(str, base, &value);
    if(res) {
        return def;
    }
    return sign * (int)value;
}
long
parse_long(
        const char *str,
        long def)
{
    int res;
    int sign = 1;
    determine_sign(&str, &sign);
    int base = 10;
    determine_base(&str, &base);
    unsigned long value;
    res = kstrtoul(str, base, &value);
    if(res) {
        return def;
    }
    return sign * (long)value;
}
long long
parse_long_long(
        const char *str,
        long long def)
{
    int res;
    int sign = 1;
    determine_sign(&str, &sign);
    int base = 10;
    determine_base(&str, &base);
    unsigned long long value;
    res = kstrtoull(str, base, &value);
    if(res) {
        return def;
    }
    return sign * (long long)value;
}
unsigned int
parse_unsigned_int(
        const char *str,
        unsigned int def)
{
    int res;
    int base = 10;
    determine_base(&str, &base);
    unsigned int value;
    res = kstrtou(str, base, &value);
    if(res) {
        return def;
    }
    return value;

}
unsigned long
parse_unsigned_long(
        const char *str,
        unsigned long def)
{
    int res;
    int base = 10;
    determine_base(&str, &base);
    unsigned long value;
    res = kstrtoul(str, base, &value);
    if(res) {
	wprintk("Failed to parse unsigned long \"%s\"\n",
		str);
        return def;
    }
    return value;

}
unsigned long long
parse_unsigned_long_long(
        const char *str,
        unsigned long long def)
{
    int res;
    int base = 10;
    determine_base(&str, &base);
    unsigned long long value;
    res = kstrtoull(str, base, &value);
    if(res) {
        return def;
    }
    return value;
}


int
kstrtoull(
        const char *str,
        int base,
        unsigned long long *out)
{
    const char *str_end = str;
    while(*str_end) {
        str_end++;
    }

    unsigned long long order_accum = 1;
    unsigned long long accum = 0;

    while(str_end != str) {
        str_end--;

        char c = *str_end;
        unsigned long long digit = -1;
        if('0' <= c && c <= '9') {
            digit = c - '0';
        } else if('a' <= c && c <= 'z') {
            digit = 10 + (c - 'a');
        } else if('A' <= c && c <= 'Z') {
            digit = 10 + (c - 'A');
        }

        if(digit >= base) {
            return -EINVAL;
        }

        accum += digit * order_accum;
        order_accum *= base;
    }

    *out = accum;
    return 0;
}

int
kstrtoul(
        const char *str,
        int base,
        unsigned long *out)
{
    int res;
    unsigned long long i;
    res = kstrtoull(str, base, &i);
    if(res) {
        return res;
    }
    *out = (unsigned int)i;
    return 0;
}
int
kstrtou(
        const char *str,
        int base,
        unsigned int *out)
{
    int res;
    unsigned long long i;
    res = kstrtoull(str, base, &i);
    if(res) {
        return res;
    }
    *out = (unsigned int)i;
    return 0;
}

