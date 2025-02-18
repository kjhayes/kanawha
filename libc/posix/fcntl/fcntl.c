
#include <stdarg.h>
#include <fcntl.h>
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
        // TODO set errno
        return -1;
    }
    return new_slot;
}

int
fcntl(int filedes, int cmd, ...)
{
    va_list arg;
    va_start(arg, cmd);
    switch(cmd) {
        case F_DUPFD:
            return __fcntl_dupfd(filedes, arg);
        default:
            break;
    }
    va_end(arg);
    return -1;
}

