
#include <stdio.h>
#include <assert.h>

#undef putchar_unlocked
int putchar_unlocked(int c)
{
    assert(stdout != NULL);
    return putc_unlocked(c, stdout);
}

#undef putchar
int putchar(int c)
{
    assert(stdout != NULL);
    return putc(c, stdout);
}

