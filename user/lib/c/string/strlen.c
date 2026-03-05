
#include <elk-libc-internal/size_t.h>
#include <stdio.h>

size_t
strlen(const char *s)
{
    size_t len = 0;
    while(*s)
    {
        len++;
        s++;
    }
    return len;
}
