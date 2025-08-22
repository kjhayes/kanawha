
#include <math.h>

double frexp(double v, int *m)
{
    return __builtin_frexp(v, m);
}

float frexpf(float v, int *m)
{
    return __builtin_frexpf(v, m);
}

long double frexpl(long double v, int *m)
{
    return __builtin_frexpl(v, m);
}

