
#include <stdio.h>

#undef getc
int getc(FILE *stream)
{
    return fgetc(stream);
}

