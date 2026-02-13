
#include <elk-libc-internal/size_t.h>

char *strcpy(
        char * restrict s1,
        const char * restrict s2)
{ 
    size_t i = 0;

    while(s2[i] != '\0') {
        s1[i] = s2[i];
        i++;
    }
    s1[i] = '\0';

    return s1;
}

