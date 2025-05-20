
#include <stdio.h>
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

int fileno(FILE *stream)
{
    return (int)stream->__fd;
}

