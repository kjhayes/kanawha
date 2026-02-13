
#include <string.h>

char *strstr(
        const char *s1,
        const char *s2)
{
    size_t s2_len = strlen(s2);

    while(*s1) {
        if(strncmp(s1, s2, s2_len) == 0) {
            return (char*)s1;
        }
        s1++;
    }

    return NULL;
}

