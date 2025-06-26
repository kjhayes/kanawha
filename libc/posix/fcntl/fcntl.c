
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

static int
__fcntl_dupfd(int src, va_list arg)
{
    int res;
    int dst = va_arg(arg, int);
    fd_t new_slot;
    res = kanawha_sys_fmove(dst, src, FMOVE_DUP, &new_slot);
    if(res) {
        errno = res;
        return -1;
    }
    return new_slot;
}

static int
__fcntl_setfl(int src, va_list arg)
{
    int res;

    int flags = va_arg(arg, int);

    unsigned long fields = 0;

    if(flags & O_NONBLOCK) {
        fields |= FACCESS_NON_BLOCKING;
    }

    res = kanawha_sys_faccess(src, fields, FACCESS_MODE_EXACT);
    if(res) {
        errno = res;
        return -1;
    }

    return 0;
}

static int
__fcntl_getfl(int src, va_list arg)
{
    int res;

    // No args

    unsigned long fields;
    res = kanawha_sys_fattr(src, FILE_ATTR_ACCESS, &fields);
    if(res) {
        errno = res;
        return -1;
    }

    return fields;
}

int
fcntl(int filedes, int cmd, ...)
{
    va_list arg;
    va_start(arg, cmd);
    switch(cmd) {
        case F_DUPFD:
            return __fcntl_dupfd(filedes, arg);
        case F_SETFL:
            return __fcntl_setfl(filedes, arg);
        case F_GETFL:
            return __fcntl_getfl(filedes, arg);
        default:
            break;
    }
    va_end(arg);
    return -1;
}

