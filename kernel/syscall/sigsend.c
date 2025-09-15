
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/signal.h>

#ifdef CONFIG_DEBUG_SYSCALL_SIGSEND
#define LOG(fmt, ...)\
    printk("PID(%ld) syscall_sigsend: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_sigsend(
        pid_t procid,
        int signal,
        unsigned long flags)
{
    int res;

    struct process *process = current_process();

    LOG("trying to send signal %d to process %ld\n",
            (s_t)signal,
            (sl_t)procid);

    res = process_send_signal(procid, signal, 0);
    if(res) {
	LOG("failed to send signal %d to process %ld (err=%s)\n",
		(s_t)signal,
		(sl_t)procid,
		errnostr(res));
        return res;
    }
    
    return 0;
}

