
#include <kanawha/sys-wrappers.h>
#include <kanawha/process.h>
#include <errno.h>

pid_t
getpgid(pid_t target)
{
    int res;
    id_t id;

    res = kanawha_sys_rid(
            target,
            RID_GID,
            &id);
    if(res) {
        errno = res;
        return -1;
    }

    return id;
}
