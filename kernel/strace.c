
#include <kanawha/strace.h>
#include <kanawha/printk.h>
#include <kanawha/syscall.h>
#include <kanawha/proc/signal.h>

void
strace_begin_syscall(
        struct process *process,
        syscall_id_t id)
{
#ifdef CONFIG_STRACE_LOG_SYSCALL_BEGIN
    printk("PID(%ld) syscall [%s]\n",
            (sl_t)process->id, syscall_id_string(id));
#endif
}

void
strace_end_syscall(
        struct process *process,
        syscall_id_t id)
{
#ifdef CONFIG_STRACE_LOG_SYSCALL_END
    printk("PID(%ld) end syscall [%s]\n",
            (sl_t)process->id, syscall_id_string(id));
#endif
}

void
strace_deliver_signal(
        struct process *process,
        signal_id_t id)
{
#ifdef CONFIG_STRACE_LOG_SIGNALS
    printk("PID(%ld) signal [%s]\n",
            (sl_t)process->id, signal_id_string(id));
#endif
}

