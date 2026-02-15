
#include <stdio.h>
#include <errno.h>

#undef getc_unlocked
int getc_unlocked(FILE *stream)
{
    return fgetc_unlocked(stream);
}

#undef getc
int getc(FILE *stream)
{
    int res = 0;
    flockfile(stream);
    res = fgetc(stream);
    funlockfile(stream);
    return res;
}


