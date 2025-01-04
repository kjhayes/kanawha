
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>

int
syscall_symlink(
        struct process *process,
        const char __user *sym_path,
        fd_t dir,
        const char __user * name,
        unsigned long flags)
{
    return -EUNIMPL;
}

