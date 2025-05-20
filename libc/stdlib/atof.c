
#include <stdlib.h>
#include <ctype.h>

double atof(const char *__nptr)
{
    const char *nptr = __nptr;

    while(isspace(*nptr)) {
        nptr++;
    }

    int negative;

    if(*nptr == '+') {
        negative = 0;
        nptr++;
    } else if(*nptr == '-') {
        negative = 1;
        nptr++;
    } else {
        negative = 0;
    }

    long long int integral_part;
    if(*nptr == '.') {
        integral_part = 0;
    } else {
        // This cast to char** is questionable
        integral_part = strtoull(nptr, (char**)&nptr, 10);
    }

    unsigned long long decimal_part;

    if(*nptr == '.') {
        nptr++;
        decimal_part = strtoull(nptr, (char**)&nptr, 10);
    } else {
        decimal_part = 0;
    }

    double val = (double)integral_part;

}

