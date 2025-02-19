
#include <kanawha/uapi/syscall.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/mmap.h>
#include <kanawha/types.h>
#include <kanawha/usermode.h>

int
syscall_spawn(
        struct process *process,
        void __user *child_func,
        void *arg,
        unsigned long flags,
        pid_t __user *child_pid)
{
    int res;

    printk("syscall_spawn: child_pid=%p\n", child_pid);

    struct process *child =
        process_spawn_child(
                process,
                child_func,
                arg,
                flags);

    if(child == NULL) {
        eprintk("syscall_spawn: process_spawn_child failed!\n");
        return -ENOMEM;
    }

    printk("spawned child %lld of parent %lld\n", (sll_t)child->id, (sll_t)process->id);

    printk("Writing PID to user address %p\n", child_pid);
    res = process_write_usermem(
            process,
            child_pid,
            &child->id,
            sizeof(pid_t));
    if(res) {
        wprintk("sys_spawn: Failed to write PID to user memory! (err=%s)\n",
                errnostr(res));
        // Still return zero because we spawned the process
    }

    return 0;
}

