
#include <stdio.h>
#include <assert.h>

#undef getchar_unlocked
int getchar_unlocked(void)
{
    assert(stdin != NULL);
    return getc_unlocked(stdin);
}

#undef getchar
int getchar(void)
{
    assert(stdin != NULL);
    return getc(stdin);
}

