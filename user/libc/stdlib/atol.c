
#include "elk-libc-internal/null.h"

extern
long int strtol(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);

long int atol(const char *nptr)
{
    return strtol(nptr, NULL, 0);
}

