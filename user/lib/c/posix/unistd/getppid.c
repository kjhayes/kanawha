
#include <kanawha/sys-wrappers.h>
#include <unistd.h>

pid_t
getppid(void)
{
    id_t pid;
    kanawha_sys_rid(0, RID_PARENT | RID_PID, &pid);
    return pid;
}
