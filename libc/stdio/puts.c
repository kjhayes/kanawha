
#include <stdio.h>

#undef puts
int puts(const char *s)
{
    int res = fputs(s, stdout);
    if(res == EOF) {
        return res;
    }
    return fputc('\n', stdout);
}

