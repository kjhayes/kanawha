
#include <string.h>

char *strrchr(
        const char *s,
        int c)
{
    size_t len = strlen(s);

    for(size_t i = len; i > 0; i--) {
        char cur = s[i-1];
        if(c == cur) {
            return ((char*)s) + (i-1);
        }
    }

    return NULL;
}

