
#include <elk-libc-internal/size_t.h>

void *
memset(void *s, int c, size_t n)
{
    void *start = s;
    void *end = s + n;
    while(s != end)
    {
        *(char*)s++ = c;
    }
    return start;
}
