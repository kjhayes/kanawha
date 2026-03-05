
extern long long int
strtoll(const char *restrict nptr, char **restrict endptr, int base);

long int
strtol(const char *restrict nptr, char **restrict endptr, int base)
{
    return (long int)strtoll(nptr, endptr, base);
}
