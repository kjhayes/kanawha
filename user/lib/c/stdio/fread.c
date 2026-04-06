
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

#include "kanawha/sys-wrappers.h"

#include <stdio.h>

#undef fread_unlocked
size_t
fread_unlocked(void *restrict ptr,
               size_t size,
               size_t nmemb,
               FILE *restrict stream)
{
    struct __sFILE *file = (struct __sFILE *)stream;

    size_t total_size = size * nmemb;

    ssize_t total_read = 0;

    while(total_size > 0)
    {
        ssize_t read =
            __elk_libc_internal__file_read(file, ptr + total_read, total_size);
        if(read < 0)
        {
            stream->error = (int)read;
            return 0;
        }
        if(read == 0)
        {
            stream->eof = 1;
            break;
        }
        total_read += read;
        total_size -= read;
    }

    // Returns the number of whole items read, not the
    // number of bytes
    return total_read / size;
}

#undef fread
size_t
fread(void *ptr, size_t size, size_t n, FILE *stream)
{
    size_t ret;
    flockfile(stream);
    ret = fread_unlocked(ptr, size, n, stream);
    funlockfile(stream);
    return ret;
}
