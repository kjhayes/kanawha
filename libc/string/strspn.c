
#include <elk-libc-internal/size_t.h>

size_t strspn(
        const char *s1,
        const char *s2)
{
    size_t i = 0;
    while(s1[i]) {
        char c = s1[i];

        const char *s2_iter = s2;
        int in_set = 0;
        while(*s2_iter) {
            if(c == *s2_iter) {
                in_set = 1;
                break;
            }
            s2_iter++;
        }

        if(!in_set) {
            break;
        }

        i++;
    }
    return i;
}

