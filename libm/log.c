
#include <math.h>

static inline double
__log_taylor(
        double x,
        unsigned long max_term)
{
    unsigned long i, n;
    double y, s, p;

    // 1-y = x -> y = 1-x
    y = 1.0 - x;

    p = y; // polynomial term
    s = 0.0; // running summation

    for(i = 0; i < max_term; i++)
    {
        n = i + 1; // nth term

        s += p / (double)(n);

        p *= y; // x^(n+1) = x^n * x
    }

    return s;
}

static inline double
__log_taylor_at(double x, double a, unsigned long max_term)
{

}

double log(double x)
{
    if(x < 0.0) {
        return NAN;
    }
    if(x == 0.0) {
        return -HUGE_VALL;
    }

    if(x < 2.0) {
        return __log_taylor(x, 32);
    }

    // This is terrible, but I'm trying to run DOOM, not cure cancer...
    unsigned long i;
    double a = M_E;
    for(i = 2; i < 512; i++) {
        double e = exp((double)i);
        if(e > x) {
            return a;
        }
        a = e;
    }
    return (double)512; // The largest double should have natural log of ~300 (if I'm not doing math wrong) so this should be fine.
}

