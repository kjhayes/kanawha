
#include <elk-libc-internal/size_t.h>

extern int tolower(int);

int strncasecmp(
        const char *s1,
        const char *s2,
        size_t n)
{
    for(size_t i = 0; i < n; i++)
    {
        char c1 = tolower(((char*)s1)[i]);
        char c2 = tolower(((char*)s2)[i]);

        if(c1 != c2) {
            return c1 - c2;
        }

        if(c1 == '\0') {
            break;
        }
    }

    return 0;

}

