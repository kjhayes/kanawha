
#include <ctype.h>
#include <stdlib.h>

double
atof(const char *__nptr)
{
    return strtod(__nptr, (char **)NULL);
}
