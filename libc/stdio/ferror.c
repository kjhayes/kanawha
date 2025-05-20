
#include <stdio.h>
#include <errno.h>
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>

#undef ferror_unlocked
int ferror_unlocked(FILE *stream)
{
    if(stream->error != 0) {
        errno = stream->error;
    }
    return stream->error;
}

#undef ferror
int ferror(FILE *stream)
{
    // TODO: Locking
    return ferror_unlocked(stream);
}

