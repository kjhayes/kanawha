
#include <assert.h>
#include <elk-libc-internal/size_t.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static char *__elk_libc_internal__strtok_iter = NULL;

char *
strtok(char *restrict s1, const char *restrict s2)
{
    if(s1 == NULL)
    {
        if(__elk_libc_internal__strtok_iter == NULL)
        {
            return NULL;
        }
        s1 = __elk_libc_internal__strtok_iter;
    }
    // Search for byte NOT in the sep string
    s1 += strspn(s1, s2);
    if(*s1 == '\0')
    {
        __elk_libc_internal__strtok_iter = NULL;
        return NULL;
    }

    // Search for a byte which IS in the sep string
    char *end = strpbrk(s1, s2);
    if(end == NULL)
    {
        __elk_libc_internal__strtok_iter = NULL;
    }
    else
    {
        __elk_libc_internal__strtok_iter = end + 1;
        *end = '\0';
    }

    return s1;
}
