
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>

int
syscall_unlink(
        struct process *process,
        fd_t dir,
        const char __user * name)
{
    return -EUNIMPL;
}

