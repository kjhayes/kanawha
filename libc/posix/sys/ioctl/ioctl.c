
#include <stdarg.h>
#include <errno.h>

int ioctl(int fildes, int request, ...)
{
    int ret;

    va_list args;
    va_start(args, request);

    switch(request) {
        default:
            errno = -EINVAL;
            ret = -1;
            break;
    }

    va_end(args);
    return ret;
}

