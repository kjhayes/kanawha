
#include "elk-libc-internal/__sFILE.h"
#include <stdio.h>

void
rewind(FILE *stream)
{
    fseek(stream, 0, SEEK_SET);
    stream->eof = 0;
    stream->error = 0;

    __elk_libc_internal__file_purge(stream);

    return;
}
