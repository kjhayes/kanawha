
#include <elk-libc-internal/size_t.h>

int memcmp(
        const void *s1,
        const void *s2,
        size_t n)
{
    for(size_t i = 0; i < n; i++) {
        char c1 = ((char*)s1)[i];
        char c2 = ((char*)s2)[i];
        if(c1 == c2) {
            continue;
        }

        return c1 - c2;
    }
    return 0;
}

