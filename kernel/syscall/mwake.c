
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>
#include <kanawha/proc/mmap.h>

int
syscall_mwake(
        void __user *addr,
        unsigned long flags)
{
    int res;

#ifdef CONFIG_DEBUG_SYSCALL_MWAKE
#define LOG(fmt, ...) printk("PID(%P) mwake: " fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

    struct process *process = current_process();
    if(flags & MWAKE_ALL) {
        LOG("waking up all (addr=%p)\n", addr);
        res = mmap_wake_all(process->mmap, (uintptr_t)addr);
        if(res) {
            LOG("failed to wake up all (addr=%p) (%e)\n", addr, res);
            return res;
        }
        LOG("woke up all (addr=%p)\n", addr);
    } else {
        LOG("waking up single (addr=%p)\n", addr);
        res = mmap_wake_single(process->mmap, (uintptr_t)addr);
        if(res) {
            LOG("failed to wake up single (addr=%p) (%e)\n", addr, res);
            return res;
        }
        LOG("woke up single (addr=%p)\n", addr);
    }
    return 0;
}

