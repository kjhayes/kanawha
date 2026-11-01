
#include <math.h>

float fabsf(float x)
{
    if(x < 0.0f) {
        return -x;
    }
    return x;
}

double fabs(double x)
{
    if(x < 0.0) {
        return -x;
    }
    return x;
}

long double fabsl(long double x)
{
    if(x < (long double)0.0) {
        return -x;
    }
    return x;
}
