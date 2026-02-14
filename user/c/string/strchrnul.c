
#include <string.h>

char *strchrnul(
        const char *s,
        int c)
{
    char *ret = strchr(s, c);
    if(ret == NULL) {
        return (char*)s + strlen(s);
    }
    return ret;
}

