
#include <stdlib.h>
#include <ctype.h>

double atof(const char *__nptr)
{
    return strtod(__nptr, (char**)NULL);
}

