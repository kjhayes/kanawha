
#include <string.h>

void *memchr(
        const void *s,
        int c,
        size_t n)
{
    for(size_t i = 0; i < n; i++) {
        char cur = ((char*)s)[i];
        if(cur == c) {
            return (void*)(s + i);
        }
    }
    return NULL;
}

