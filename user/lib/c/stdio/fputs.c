
#include <elk-libc-internal/FILE.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>

#include <stdio.h>
#include <string.h>

#undef fputs_unlocked
int
fputs_unlocked(const char *restrict s, FILE *restrict stream)
{
    size_t len = strlen(s);

    while(len > 0)
    {
        ssize_t written;
        written = kanawha_sys_write(stream->__fd, (void *)s, len);
        if(written <= 0)
        {
            // TODO set FILE error
            return EOF;
        }
        len -= written;
        s += written;
    }

    return 0;
}

#undef fputs
int
fputs(const char *restrict s, FILE *restrict stream)
{
    int res;
    flockfile(stream);
    res = fputs_unlocked(s, stream);
    funlockfile(stream);
    return res;
}
