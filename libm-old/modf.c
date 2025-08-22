
#include <math.h>

double modf(double v, double *r)
{
    return __builtin_modf(v, r);
}
float modff(float v, float *r)
{
    return __builtin_modff(v, r);
}
long double modfl(long double v, long double *r)
{
    return __builtin_modfl(v, r);
}

