
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>
#include <kanawha/proc/mmap.h>

int
syscall_mwait(
        void __user *addr,
        unsigned long flags)
{
    int res;

#ifdef CONFIG_DEBUG_SYSCALL_MWAIT
#define LOG(fmt, ...) printk("PID(%P) mwait: " fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

    LOG("waiting (addr=%p)\n", addr);
    struct process *process = current_process();
    res = mmap_wait_on(process->mmap, (uintptr_t)addr);
    if(res) {
        LOG("interrupted (addr=%p) (%e)\n", addr, res);
        return res;
    }
    LOG("woke up (addr=%p)\n", addr);
    return 0;
}

