
#include <math.h>

float fabsf(float x)
{
    if(x < 0.0f) {
        return -x;
    }
    return x;
}
