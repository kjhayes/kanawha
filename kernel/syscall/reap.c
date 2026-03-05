
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>

#ifdef CONFIG_DEBUG_SYSCALL_REAP
#define LOG(fmt, ...)                                                          \
    printk("PID(%ld) syscall_reap: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_reap(unsigned long flags,
             pid_t __user *pid_inout,
             int __user *user_exitcode)
{
    int res;

    struct process *process = current_process();

    int nowait = (flags & REAP_NON_BLOCKING);

    LOG("flags=0x%lx, nowait=%d\n", flags, nowait);

    pid_t to_reap_id;

    if(flags & REAP_ANY)
    {
        res = process_get_reapable_child(process, nowait, &to_reap_id);
        if(res)
        {
            LOG("process_get_reapable_child returned (%s)!\n", errnostr(res));
            return res;
        }
    }
    else
    {
        res = process_read_usermem(process,
                                   &to_reap_id,
                                   pid_inout,
                                   sizeof(pid_t));
        if(res)
        {
            LOG("process_read_usermem returned (%s)!\n", errnostr(res));
            return res;
        }
    }

    LOG("reaping child pid=%ld\n", to_reap_id);

    int exitcode;
    res = process_reap_child(process, to_reap_id, &exitcode, nowait);
    if(res)
    {
        LOG("failed to reap child! (err=%s)\n", errnostr(res));
        return res;
    }

    LOG("reaped child with exitcode=%d\n", exitcode);

    res = process_write_usermem(process, user_exitcode, &exitcode, sizeof(int));
    if(res)
    {
        LOG("failed to copy process exitcode to userspace! (err=%s)\n",
            errnostr(res));
        // We did reap the process,
        // but the user passed us an invalid location to write,
        // so for now we'll consider that a success and still return zero
    }

    if(flags & REAP_ANY)
    {
        res =
            process_write_usermem(process, pid_inout, &to_reap_id, sizeof(int));
        if(res)
        {
            LOG("failed to copy reaped PID to userspace! (err=%s)\n",
                errnostr(res));
            // We did reap the process,
            // but the user passed us an invalid location to write,
            // so for now we'll consider that a success and still
            // return zero
        }
    }

    return 0;
}
