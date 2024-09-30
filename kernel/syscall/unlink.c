
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_unlink(
        struct process *process,
        fd_t dir,
        char __user * name)
{
    return -EUNIMPL;
}

