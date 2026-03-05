
#include <stdio.h>

int
fgetpos(FILE *restrict stream, fpos_t *restrict pos)
{
    int res;
    pos->__offset = ftell(stream);
    return 0;
}
