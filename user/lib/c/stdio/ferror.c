
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>
#include <errno.h>
#include <stdio.h>

#undef ferror_unlocked
int
ferror_unlocked(FILE *stream)
{
    if(stream->error != 0)
    {
        errno = stream->error;
    }
    return stream->error;
}

#undef ferror
int
ferror(FILE *stream)
{
    int res;
    flockfile(stream);
    res = ferror_unlocked(stream);
    funlockfile(stream);
    return res;
}
