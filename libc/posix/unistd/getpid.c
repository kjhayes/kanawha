
#include <unistd.h>
#include <kanawha/sys-wrappers.h>

pid_t getpid(void)
{
    id_t pid;
    kanawha_sys_rid(
            0,
            RID_SELF|RID_PID,
            &pid);
    return pid;
}

