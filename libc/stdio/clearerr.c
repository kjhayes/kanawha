
#include <stdio.h>
#include "elk-libc-internal/__sFILE.h"

void clearerr(FILE *stream)
{
    stream->eof = 0;
}

