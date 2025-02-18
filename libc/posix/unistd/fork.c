
#include <unistd.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/spawn.h>

extern void
__elk_posix__do_fork(pid_t *pid_out);

pid_t
fork(void)
{

    pid_t pid = 0;
    __elk_posix__do_fork(&pid);
    return pid;
}
