
#include <elk-libc-internal/size_t.h>

void *memcpy(
        void * restrict s1,
        const void * restrict s2,
        size_t n)
{
    for(size_t i = 0; i < n; i++) {
        ((char*)s1)[i] = ((char*)s2)[i];
    }
    return s1;
}

