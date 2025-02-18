
extern long long int strtoll(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);

unsigned long long int strtoull(
        const char * restrict nptr,
        char ** restrict endptr,
        int base)
{
    return (unsigned long long int)strtoll(nptr, endptr, base);
}
