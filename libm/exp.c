
static inline double
__exp_taylor(double x, unsigned long max_term)
{
    unsigned long i, n;
    double e, p, f;

    p = x; // polynomial term
    e = 1.0; // running summation
    f = 1.0; // factorial

    for(i = 0; i < max_term; i++)
    {
        n = i + 1; // nth term

        e += (1.0/f) * p;

        p *= x; // x^(n+1) = x^n * x
        f *= (double)(n+1); // (n+1)! = n! * (n+1)
    }

    return e;
}

double exp(double x) {
    // This is not a good "exp"
    // but it should work for now...
    if(x == 0.0) {
        return 1.0;
    }
    return __exp_taylor(x, 32);
}

