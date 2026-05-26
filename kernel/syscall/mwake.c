
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>
#include <kanawha/proc/mmap.h>

#define LOG(...)

int
syscall_mwake(
        void __user *addr,
        unsigned long flags)
{
    int res;
    struct process *process = current_process();
    if(flags & MWAKE_ALL) {
        LOG("PID(%P): mwake waking up all\n");
        res = mmap_wake_all(process->mmap, (uintptr_t)addr);
        if(res) {
            LOG("PID(%P): mwake failed to wake up all (%e)\n", res);
            return res;
        }
        LOG("PID(%P): mwake woke up all\n");
    } else {
        LOG("PID(%P): mwake waking up single\n");
        res = mmap_wake_single(process->mmap, (uintptr_t)addr);
        if(res) {
            LOG("PID(%P): mwake failed to wake up single (%e)\n", res);
            return res;
        }
        LOG("PID(%P): mwake woke up single\n");
    }
    return 0;
}

