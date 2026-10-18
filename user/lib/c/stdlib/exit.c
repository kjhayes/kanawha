
#include <elk-libc-internal/atexit.h>
#include <kanawha/syscall.h>
#include <stdlib.h>

void
exit(int status)
{
    __elk_libc_internal__do_atexit();
    kanawha_sys_exit(status);
}

void
_exit(int status)
{
    kanawha_sys_exit(status);
}
