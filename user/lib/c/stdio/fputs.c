
#include <elk-libc-internal/__sFILE.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>

#include <stdio.h>
#include <string.h>

#undef fputs_unlocked
int fputs_unlocked(const char * restrict s, FILE * restrict stream)
{
    struct __sFILE *file = (struct __sFILE *)stream;

    size_t len = strlen(s);

    while(len > 0) {
        ssize_t written;
        written = kanawha_sys_write(
                file->__fd,
                (void*)s,
                len);
        if(written <= 0) {
            // TODO set FILE error
            return EOF;
        }
        len -= written;
        s += written;
    }

    return 0;
}

#undef fputs
int fputs(const char * restrict s, FILE * restrict stream)
{
    int res;
    flockfile(stream);
    res = fputs_unlocked(s, stream);
    funlockfile(stream);
    return res;
}

