
#include <elk-libc-internal/size_t.h>

size_t strcspn(
        const char *s1,
        const char *s2)
{
    size_t i = 0;
    while(s1[i]) {
        char c = s1[i];

        const char *s2_iter = s2;
        while(*s2_iter) {
            if(c == *s2_iter) {
                return i;
            }
            s2_iter++;
        }

        i++;
    }
    return i;
}

