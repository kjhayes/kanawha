
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_mkdir(
        struct process *process,
        fd_t dir,
        char __user * name,
        unsigned long flags)
{
    return -EUNIMPL;
}

