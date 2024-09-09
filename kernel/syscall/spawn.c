
#include <kanawha/uapi/syscall.h>
#include <kanawha/uapi/spawn.h>
#include <kanawha/process.h>
#include <kanawha/syscall/mmap.h>
#include <kanawha/stdint.h>
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

    dprintk("syscall_spawn: child_pid=%p\n", child_pid);

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

    dprintk("Spawned Child %lld\n", (sll_t)child->id);

    dprintk("Writing PID to user address %p\n", child_pid);
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

