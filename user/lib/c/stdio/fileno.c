
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"
#include <stdio.h>

#undef fileno_unlocked
int
fileno_unlocked(FILE *stream)
{
    return (int)stream->__fd;
}

#undef fileno
int
fileno(FILE *stream)
{
    int res;
    flockfile(stream);
    res = fileno_unlocked(stream);
    funlockfile(stream);
    return res;
}
