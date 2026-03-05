
#include <errno.h>
#include <kanawha/process.h>
#include <kanawha/sys-wrappers.h>
#include <unistd.h>

int
setpgid(pid_t target, pid_t pgid)
{
    int res;

    res = kanawha_sys_wid(target, RID_GID, pgid);
    if(res)
    {
        errno = res;
        return -1;
    }

    return 0;
}
