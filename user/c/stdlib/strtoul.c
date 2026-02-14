
extern long long int strtoll(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);

unsigned long int strtoul(
        const char * restrict nptr,
        char ** restrict endptr,
        int base)
{
    return (unsigned long int)strtoll(nptr, endptr, base);
}

