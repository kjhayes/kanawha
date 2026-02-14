
#include <string.h>

char *strchr(
        const char *s,
        int c)
{
    do {
        if(*s == c) {
            return (char*)s;
        }
        if(*s == '\0') {
            break;
        }
        s++;
    } while(1);

    return NULL;
}

