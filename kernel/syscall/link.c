
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>

int
syscall_link(
        struct process *process,
        fd_t from,
        fd_t dir,
        const char __user * link_name,
        unsigned long flags)
{
    return -EUNIMPL;
}

