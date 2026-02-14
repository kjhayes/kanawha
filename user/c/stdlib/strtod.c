
#include <stdlib.h>
#include <ctype.h>

#define PLUS  '+'
#define MINUS '-'
#define RADIX '.'
#define EXPONENT_0 'e'
#define EXPONENT_1 'E'

double strtod(const char *nptr, char ** restrict endptr)
{
    while(isspace(*nptr)) {
        nptr++;
    }

    int negative;

    if(*nptr == PLUS) {
        negative = 0;
        nptr++;
    } else if(*nptr == MINUS) {
        negative = 1;
        nptr++;
    } else {
        negative = 0;
    }

    unsigned long long integral_part;
    if(*nptr == RADIX) {
        integral_part = 0;
    } else {
        // This cast to char** is questionable
        integral_part = strtoull(nptr, (char**)&nptr, 10);
    }

    unsigned long long decimal_part;

    if(*nptr == RADIX) {
        nptr++;
        decimal_part = strtoull(nptr, (char**)&nptr, 10);
    } else {
        decimal_part = 0;
    }

    double val = (double)integral_part;

    double decimal_val = decimal_part;
    {
    double decimal_divisor = 1;
    while(decimal_part > 0) {
        decimal_divisor *= 10;
        decimal_part /= 10;
    }
    decimal_val /= decimal_divisor;
    }

    val += decimal_val;

    // deal with exponents
    if((*nptr == EXPONENT_0 || *nptr == EXPONENT_1)
       && isdigit(nptr[1])) 
    {
        nptr++; // consume the "e" or "E"
        long long exp = strtoll(nptr, (char**)&nptr, 10);
        if(exp > 1000) {
            exp = 1000; // This is more than large enough already to saturate any reasonable floating point width...
        }
        if(exp < -1000) {
            exp = -1000; // This is more than small enough to round to zero...
        }
        if(exp > 0) {
            for(unsigned long long __x = 0; __x < exp; __x++) {
                val *= 10.0;
            }
        } else if(exp < 0) {
            for(unsigned long long __x = 0; __x < -exp; __x++) {
                val *= 0.1;
            }
        } else {
            val = 0.0;
        }
    }

    if(endptr != NULL) {
        *endptr = (char*)nptr;
    }

    return val;
}

