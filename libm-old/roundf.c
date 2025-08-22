
#include <math.h>

double round(double v)
{
    return __builtin_round(v);
}
float roundf(float v)
{
    return __builtin_roundf(v);
}
long double roundl(long double v)
{
    return __builtin_roundl(v);
}

long lround(double v)
{
    return __builtin_lround(v);
}
long lroundf(float v)
{
    return __builtin_lroundf(v);
}
long lroundl(long double v)
{
    return __builtin_lroundl(v);
}

long long llround(double v)
{
    return __builtin_llround(v);
}
long long llroundf(float v)
{
    return __builtin_llroundf(v);
}
long long llroundl(long double v)
{
    return __builtin_llroundl(v);
}

