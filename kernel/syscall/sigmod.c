
#include <kanawha/proc/process.h>
#include <kanawha/proc/signal.h>
#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/syscall.h>

#ifdef CONFIG_DEBUG_SYSCALL_SIGMOD
#define LOG(fmt, ...)                                                          \
    printk("PID(%ld) syscall_sigmod: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_sigmod(unsigned long attr, unsigned long value)
{
    int res;

    struct process *process = current_process();

    switch(attr)
    {
    case SIGMOD_ENTRY:
        LOG("SIGMOD_ENTRY (entry_addr=%p)\n", (void __user *)value);
        res = signal_set_entry(process, (void __user *)value);
        if(res)
        {
            return res;
        }
        return 0;
    case SIGMOD_ACK:
        LOG("SIGMOD_ACK (signal=%lu)\n", value);
        res = signal_ack(process, (signal_id_t)value);
        if(res)
        {
            return res;
        }
        return 0;
    default:
        LOG("unknown attr=%lu\n", attr);
        return -EUNIMPL;
    }
}
