
#include <unistd.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/spawn.h>

extern int
__elk_posix__do_fork(pid_t *pid_out);

pid_t
fork(void)
{

    int res;
    pid_t pid = 0;
    res = __elk_posix__do_fork(&pid);
    if(res) {
        // TODO set errno
        return -1;
    }
    return pid;
}
