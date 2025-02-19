
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

    while(file->peek_datalen > 0 && total_size > 0) {
        *(char*)ptr = __elk_libc_internal__file_getc(file);
        ptr++;
        total_size--;
        total_read++;
    }

    while(total_size > 0) {
        ssize_t read = __elk_libc_internal__file_read(
                file,
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

