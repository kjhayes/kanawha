
#include <fcntl.h>
#include <stdarg.h>
#include <kanawha/file.h>

extern int
__elk_doopen(
        const char *pathname,
        int flags,
	va_list args,
	fd_t *dir_fd);


int
openat(int fd, const char * pathname, int flags, ...)
{
    int res;
    fd_t dir_fd = fd;
    va_list args;
    va_start(args, flags);
    res = __elk_doopen(
	    pathname,
	    flags,
	    args,
	    &dir_fd);
    va_end(args);
    return res;
}
