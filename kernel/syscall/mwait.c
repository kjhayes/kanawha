
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>
#include <kanawha/proc/mmap.h>

#define LOG(...)

int
syscall_mwait(
        void __user *addr,
        unsigned long flags)
{
    int res;
    LOG("PID(%P): mwait waiting\n");
    struct process *process = current_process();
    res = mmap_wait_on(process->mmap, (uintptr_t)addr);
    if(res) {
        LOG("PID(%P): mwait interrupted (%e)\n", res);
        return res;
    }
    LOG("PID(%P): mwait woke up\n");
    return 0;
}

