
#include "elk-libc-internal/null.h"
#include <stdio.h>

extern int
isspace(int c);

static int
interp_char(char c, int base)
{
    int value = -1;
    if('0' <= c && c <= '9')
    {
        value = c - '0';
    }
    else if('a' <= c && c <= 'z')
    {
        value = 10 + (c - 'a');
    }
    else if('A' <= c && c <= 'Z')
    {
        value = 10 + (c - 'A');
    }
    return value;
}

long long int
strtoll(const char *restrict nptr, char **restrict endptr_out, int base)
{
    // Skip initial whitespace
    while(*nptr != '\0' && isspace(*nptr))
    {
        nptr++;
    }

    // Handle optional (+/-)
    long long int sign = 1;
    if(*nptr == '-')
    {
        sign = -1;
        nptr++;
    }
    else if(*nptr == '+')
    {
        nptr++;
    }

    // Infer the base from a prefix (default to base 10 if no prefix is found)
    if(base == 0)
    {
        if(*nptr == '0')
        {
            if(*(nptr + 1) == 'x' || *(nptr + 1) == 'X')
            {
                base = 16;
            }
            else
            {
                base = 8;
            }
        }
        else
        {
            base = 10;
        }
    }

    // Get rid of hexadecimal prefix if it is present
    if(base == 16)
    {
        if(*nptr == '0')
        {
            if(*(nptr + 1) == 'x' || *(nptr + 1) == 'X')
            {
                nptr += 2;
            }
        }
    }

    // Get rid of any leading zero(s) for the sake of performance
    while(*nptr == '0')
    {
        nptr++;
    }

    // Find the first character which does not fit our system
    const char *endptr = nptr;
    while(*endptr && (interp_char(*endptr, base) >= 0))
    {
        endptr++;
    }

    long long int value = 0;
    int order = 0;

    // Reverse iterator
    const char *riter = endptr - 1;

    do
    {

        char c = *riter;
        long long int digit_value = interp_char(c, base);

        // Don't bother computing the power for zero(s)
        if(digit_value > 0)
        {
            for(int i = 0; i < order; i++)
            {
                digit_value *= base;
            }
        }

        value += digit_value;

        order++;

        riter--;
    } while(riter >= nptr);

    if(endptr_out != NULL)
    {
        *endptr_out = (char *)endptr;
    }

    long long int final = value * sign;
    return final;
}
