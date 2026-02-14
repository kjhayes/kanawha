
#include <string.h>

char *strncat(
        char * restrict s1,
        const char * restrict s2,
        size_t n)
{
    size_t s1_len = strlen(s1);
    strncpy(s1+s1_len, s2, n);
    ((char*)s1)[s1_len + n] = '\0';
    return s1;
}

