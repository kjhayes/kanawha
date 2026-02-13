
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <kanawha/errno.h>
#include <fcntl.h>
#include <stdarg.h>

extern int
__elk_doopen(
        const char *pathname,
        int flags,
	va_list args,
	fd_t *dir_fd);

int
open(
        const char *pathname,
        int flags,
        ...)
{
    int res;
    va_list args;
    va_start(args, flags);
    res = __elk_doopen(
	    pathname,
	    flags,
	    args,
	    NULL);
    va_end(args);
    return res;
}

