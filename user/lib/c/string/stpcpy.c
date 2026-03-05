
#include <stdlib.h>
#include <string.h>

char *
stpcpy(char *dest, const char *src)
{
    size_t len = strlen(src);
    memcpy(dest, src, len + 1);
    return dest + len;
}
