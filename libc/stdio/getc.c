
#include <stdio.h>

#undef getc_unlocked
int getc_unlocked(FILE *stream)
{
    return fgetc_unlocked(stream);
}

#undef getc
int getc(FILE *stream)
{
    return fgetc(stream);
}


