
#include <unistd.h>
#include <errno.h>

ssize_t readlink(
        const char * restrict,
        char * restrict,
        size_t)
{
    errno = -EUNIMPL;
    return -1;
}

