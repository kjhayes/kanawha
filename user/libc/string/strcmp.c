
#include <elk-libc-internal/size_t.h>

int strcmp(
        const char *s1,
        const char *s2)
{
    char c1, c2;
    do {
        c1 = *((char*)s1);
        c2 = *((char*)s2);

        if(c1 != c2) {
            return c1 - c2;
        }

        s1++;
        s2++;
    } while(c1 != '\0');

    return 0;
}

