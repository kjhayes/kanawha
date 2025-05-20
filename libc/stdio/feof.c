
#include <stdio.h>
#include <elk-libc-internal/FILE.h>
#include <elk-libc-internal/__sFILE.h>

int feof(FILE *stream)
{
    if(stream->eof) {
        return 1;
    }
    return 0;
}

