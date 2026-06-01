
#include <kanawha/attribute.h>
#include <kanawha/proc/process.h>
#include <kanawha/thread.h>
#include <kanawha/usermode.h>

__noreturn void
enter_usermode(void *arg)
{
    struct process *process = current_process();

    if(process == NULL)
    {
        panic("CPU (%ld) called enter_usermode without a process!\n",
              (sl_t)current_cpu_id());
    }

    /*
     * This little "gap" here allows for an interrupt to occur while we are a
     * "user" thread, but we actually were still running in kernel mode, so
     * note, THREAD_FLAG_USER does not mean we must have been running user-mode
     * when an interrupt/exception occurs
     */

    dprintk("enter_usermode: ip=%p, arg=%p\n",
            process->user_ip,
            arg);
    arch_enter_usermode(process->user_ip, arg);
}
