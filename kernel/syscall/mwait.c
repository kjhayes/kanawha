
#include <kanawha/syscall.h>
#include <kanawha/uapi/mwait.h>

int
syscall_mwait(
        void __user *addr,
        unsigned long flags)
{
    // Trivial implementation (no blocking)
    // for now...
    printk("PID(%P) mwait\n");
    return 0;
}

