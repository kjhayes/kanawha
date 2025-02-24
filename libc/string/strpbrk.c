
#include <string.h>

char *strpbrk(
        const char *s1,
        const char *s2)
{
    while(*s1) {

        const char *s2_iter = s2;
        while(*s2_iter) {
            if(*s2_iter == *s1) {
                return (char*)s1;
            }
            s2_iter++;
        }

        s1++;
    }
    return NULL;
}

