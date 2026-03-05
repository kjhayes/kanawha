
#include "elk-libc-internal/null.h"

extern long long int
strtoll(const char *restrict nptr, char **restrict endptr, int base);

long long int
atoll(const char *nptr)
{
    return strtoll(nptr, NULL, 0);
}
