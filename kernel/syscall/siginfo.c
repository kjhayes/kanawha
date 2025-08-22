
#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/proc/signal.h>
#include <kanawha/proc/process.h>

#ifdef CONFIG_DEBUG_SYSCALL_SIGINFO
#define LOG(fmt, ...)\
    printk("PID(%ld) syscall_siginfo: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_siginfo(
        struct process *process,
	unsigned long attr,
	unsigned long __user *value)
{
    int res;
    unsigned long ret;

    switch(attr) {
	case SIGINFO_RETURN:
	    ret = (unsigned long)process_signal_return_addr(process);
	    LOG("SIGINFO_RETURN (0x%lx)\n", ret);
	    break;
	case SIGINFO_CURRENT:
	    ret = (unsigned long)process_current_signal(process);
	    LOG("SIGINFO_CURRENT (%s)\n", signal_id_string(ret));
	    break;
	default:
	    return -EINVAL;
    }

    res = process_write_usermem(process, value, &ret, sizeof(ret));
    if(res) {
	LOG("failed to write to userspace!\n");
	return res;
    }

    return 0;
}

