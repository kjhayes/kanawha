
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_link(
        struct process *process,
        fd_t from,
        fd_t dir,
        char __user * link_name,
        unsigned long flags)
{
    return -EUNIMPL;
}

