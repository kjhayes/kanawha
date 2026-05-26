
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>

int
syscall_mwake(
        void __user *addr,
        unsigned long flags)
{
    // Trivial implementation (no blocking)
    // for now...
    printk("PID(%P) mwake\n");
    return 0;
}

