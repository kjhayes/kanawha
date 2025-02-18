
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/__sFILE.h"

#include "kanawha/sys-wrappers.h"

#include <stdio.h>

size_t
fread(
        void * restrict ptr,
        size_t size,
        size_t nmemb,
        FILE * restrict stream)
{
    struct __sFILE *file = (struct __sFILE*)stream;

    size_t total_size = size * nmemb;

    ssize_t total_read = 0;

    while(total_size > 0) {
        ssize_t read = kanawha_sys_read(
                stream->__fd,
                ptr + total_read,
                total_size);
        if(read < 0) {
            // TODO: Setup ferror()
            return 0;
        }
        if(read == 0) {
            // TODO: Setup feof()
            break;
        }
        total_read += read;
        total_size -= read;
    }

    // Returns the number of whole items read, not the
    // number of bytes
    return total_read / size;
}

