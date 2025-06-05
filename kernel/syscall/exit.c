
#include <kanawha/syscall.h>
#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/proc/process.h>
#include <kanawha/thread.h>
#include <kanawha/attribute.h>

__noreturn
void
syscall_exit(
        struct process *process,
        int exitcode)
{
    int res;

    res = process_terminate(process, exitcode);
    if(res) {
        panic("PID(%ld) syscall_exit: process_terminate(%d) -> %s, user_ip=%p\n",
              process->id, exitcode, errnostr(res), process->user_ip);
    }

#ifdef CONFIG_DEBUG_SYSCALL_EXIT
    printk("Exiting PID(%ld) (exitcode=%d)\n", process->id, exitcode);
#endif

    thread_abandon(force_resched());
    panic("PID(%ld) syscall_exit: thread_abandon returned!\n",
            (sl_t)process->id);
}

