
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_symlink(
        struct process *process,
        const char __user *sym_path,
        fd_t dir,
        char __user * name,
        unsigned long flags)
{
    return -EUNIMPL;
}

