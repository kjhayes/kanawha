
#include <elk-libc-internal/size_t.h>

char *
strncpy(char *restrict s1, const char *restrict s2, size_t n)
{
    for(size_t i = 0; i < n; i++)
    {
        s1[i] = *(char *)s2;
        if(*(char *)s2)
        {
            s2++;
        }
    }
    return s1;
}
