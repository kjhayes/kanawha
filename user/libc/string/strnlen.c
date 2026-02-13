
#include <stdio.h>
#include <elk-libc-internal/size_t.h>

size_t strnlen(
        const char *s,
        size_t maxlen)
{
    size_t len = 0;
    while(len < maxlen && *s) {
        len++;
        s++;
    }
    return len;
}

