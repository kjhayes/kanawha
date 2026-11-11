
#include <elk-libc-internal/FILE.h>
#include <stdio.h>

void
clearerr_unlocked(FILE *stream)
{
    stream->eof = 0;
}

void
clearerr(FILE *stream)
{
    flockfile(stream);
    clearerr_unlocked(stream);
    funlockfile(stream);
}
