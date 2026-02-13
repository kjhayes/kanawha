
#include <string.h>

char *strcat(
        char * restrict s1,
        const char * restrict s2)
{
    size_t s1_len = strlen(s1);
    strcpy(s1+s1_len, s2);
    return s1;
}

