
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/process.h>

int kill(pid_t pid, int sig)
{
    int res;

    if(pid < 0) {
        errno = -EUNIMPL;
        return -1;
    }

    res = kanawha_sys_sigsend(
            pid,
            sig,
            0);
    if(res) {
        errno = res;
        return -1;
    }

    return 0;
}

