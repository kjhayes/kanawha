
#include <kanawha/syscall.h>
#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/process.h>
#include <kanawha/thread.h>

__attribute__((noreturn))
void
syscall_exit(
        struct process *process,
        int exitcode)
{
    int res;
    res = process_terminate(process, exitcode);
    if(res) {
        eprintk("syscall_exit: process_terminate(%p, %d) -> %s\n",
                process, exitcode, errnostr(res));
    }

#ifdef CONFIG_DEBUG_SYSCALL_EXIT
    printk("Exiting PID(%ld) (exitcode=%d)\n", process->id, exitcode);
#endif

    thread_abandon(force_resched());
}

