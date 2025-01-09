
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>

int
syscall_mcreate(
        struct process *process,
        unsigned long flags,
        ad_t __user *aspace)
{
    return -EUNIMPL;
}

