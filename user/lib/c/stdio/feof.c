
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>
#include <stdio.h>

#undef feof_unlocked
int
feof_unlocked(FILE *stream)
{
    if(stream->eof)
    {
        return 1;
    }
    return 0;
}

#undef feof
int
feof(FILE *stream)
{
    int res;
    flockfile(stream);
    res = feof_unlocked(stream);
    funlockfile(stream);
    return res;
}
