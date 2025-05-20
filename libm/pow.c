
#include <math.h>

double pow(
        double base,
        double power)
{
    // Hehehe... this is garbage...
    double ln_base = log(base);
    return exp(ln_base * power);
}

