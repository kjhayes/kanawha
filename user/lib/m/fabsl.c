
#include <math.h>

long double fabsl(long double x)
{
    if(x < 0.0) {
        return -x;
    }
    return x;
}

