
#include <kanawha/usermode.h>
#include <kanawha/thread.h>
#include <kanawha/process.h>

__attribute__((noreturn))
void enter_usermode(void __user *starting_address, void *arg)
{
    struct process *process = current_process();

    if(process == NULL) {
        panic("CPU (%ld) called enter_usermode without a process!\n",
                (sl_t)current_cpu_id());
    }

    /*
     * This little "gap" here allows for an interrupt to occur while we are a "user"
     * thread, but we actually were still running in kernel mode,
     * so note, THREAD_FLAG_USER does not mean we must have been running user-mode
     * when an interrupt/exception occurs
     */

    void __user *ip = starting_address;

    spin_lock(&process->signal_lock);
    if(process->forcing_ip) {
        ip = (void __user *)process->forced_ip;
        process->forcing_ip = 0;
    }
    spin_unlock(&process->signal_lock);

    arch_enter_usermode(ip, arg);
}

