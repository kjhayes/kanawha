
#include "elk-libc-internal/null.h"

extern
long int strtol(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);

int atoi(const char *nptr)
{
    return (int)strtol(nptr, NULL, 0);
}

