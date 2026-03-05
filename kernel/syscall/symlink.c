
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_symlink(const char __user *sym_path,
                fd_t dir,
                char __user *name,
                unsigned long flags)
{
    struct process *process = current_process();
    return -EUNIMPL;
}
