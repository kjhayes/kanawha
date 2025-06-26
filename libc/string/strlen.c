
#include <stdio.h>
#include <elk-libc-internal/size_t.h>

size_t strlen(
        const char *s)
{
    size_t len = 0;
    while(*s) {
        len++;
        s++;
    }
    return len;
}

