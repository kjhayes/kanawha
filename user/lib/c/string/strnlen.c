
#include <elk-libc-internal/size_t.h>
#include <stdio.h>

size_t
strnlen(const char *s, size_t maxlen)
{
    size_t len = 0;
    while(len < maxlen && *s)
    {
        len++;
        s++;
    }
    return len;
}
