
#include <stdio.h>
#include "elk-libc-internal/__sFILE.h"

void
rewind(FILE *stream)
{
    fseek(stream, 0, SEEK_SET);
    stream->eof = 0;
    stream->error = 0;
    if(stream->peek_buflen > 0) {
        free(stream->peek_buffer);
        stream->peek_buflen = 0;
        stream->peek_buffer = NULL;
    }
    return;
}

