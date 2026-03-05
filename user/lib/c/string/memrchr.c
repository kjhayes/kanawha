
#include <string.h>

void *
memrchr(const void *_s, int c, size_t n)
{
    if(n == 0)
    {
        return NULL;
    }

    const char *s = _s;

    const char *cur;
    do
    {
        n--;
        cur = s + n;
        if(*cur == c)
        {
            return (void *)cur;
        }
    } while(n > 0);

    return NULL;
}
