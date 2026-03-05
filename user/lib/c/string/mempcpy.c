
#include <string.h>

void *
mempcpy(void *dest, const void *src, size_t n)
{
    void *end = dest + n;
    memcpy(dest, src, n);
    return end;
}
