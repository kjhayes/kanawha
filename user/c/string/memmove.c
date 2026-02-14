
#include <elk-libc-internal/size_t.h>

void *memmove(
        void *s1,
        const void *s2,
        size_t n)
{
    if(s1 < s2) {
        for(size_t i = 0; i < n; i++) {
            ((char*)s1)[i] = ((char*)s2)[i];
        }
    } else if(s1 > s2) {
        // Reverse Order
        for(size_t i = n; i > 0; i--) {
            ((char*)s1)[i-1] = ((char*)s2)[i-1];
        }
    } else { // s1 == s2
        // Nothing to do
    }
    return s1;
}

