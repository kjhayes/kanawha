
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

#include "kanawha/sys-wrappers.h"

#include <stdio.h>

#undef fwrite_unlocked
size_t
fwrite_unlocked(
        const void * restrict ptr,
        size_t size,
        size_t nmemb,
        FILE * restrict stream)
{
    struct __sFILE *file = (struct __sFILE*)stream;

    size_t total_size = size * nmemb;
    ssize_t total_written = 0;

    while(total_size > 0) {
        ssize_t written = kanawha_sys_write(
                stream->__fd,
                ptr + total_written,
                total_size);
        if(written < 0) {
            stream->error = (int)written;
            break;
        }
        if(written == 0) {
            stream->eof = 1;
            break;
        }
        total_written += written;
        total_size -= written;
    }

    // Returns the number of whole items written, not the
    // number of bytes
    return total_written / size;
}

#undef fwrite
size_t
fwrite(
        const void * restrict ptr,
        size_t size,
        size_t nmemb,
        FILE * restrict stream)
{
    size_t ret;
    flockfile(stream);
    ret = fwrite_unlocked(ptr, size, nmemb, stream);
    funlockfile(stream);
    return ret;
}

