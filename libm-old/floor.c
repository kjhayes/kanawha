
double floor(double x) {
    // TODO: I am not convinced this is correct,
    //       the largest representable "integer" double
    //       is much larger than the largest unsigned long long
    //       (assuming it is no longer than 128bits, though 
    //        even worse it is probably only 64-bit)
    //       So for very large double values, this is wrong
    return (double)(unsigned long long)x;
}

