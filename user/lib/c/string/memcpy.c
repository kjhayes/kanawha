
#include <elk-libc-internal/size_t.h>
#include <kanawha/types.h>

static void *
__memcpy_bytewise(
        void *restrict s1, const void *restrict s2, size_t n)
{
    void *start = s1;
    void *s1_end = s1 + n;
    while(s1 != s1_end)
    {
        *((char *)s1++) = *(char *)s2++;
    }
    return start;
}

void *
memcpy(void *restrict s1, const void *restrict s2, size_t n)
{
    uintptr_t alignmask = sizeof(unsigned long)-1;
    if((n & alignmask) || ((uintptr_t)s1 & alignmask) || ((uintptr_t)s2 & alignmask))
    {
        // Not a multiple of unsigned longs
        return __memcpy_bytewise(s1,s2,n);
    }
    else {
        unsigned long *restrict l1 = s1;
        const unsigned long *restrict l2 = s2;
        const unsigned long *l1_end = (unsigned long *)(s1 + n);
        while(l1 != l1_end) {
            *l1++ = *l2++;
        }
        return s1;
    }
}
