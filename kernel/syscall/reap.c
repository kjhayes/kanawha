
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>

int
syscall_reap(
        struct process *process,
        unsigned long flags,
        pid_t __user *pid_inout,
        int __user *user_exitcode)
{
    int res;

    dprintk("syscall_reap: PID(%lld)\n", to_reap_id);

    int nowait = (flags & REAP_NON_BLOCKING);

    pid_t to_reap_id;

    if(flags & REAP_ANY) {
        res = process_get_reapable_child(
                process,
                nowait,
                &to_reap_id);
        if(res) {
            return res;
        }
    } else {
        res = process_read_usermem(
                process,
                &to_reap_id,
                pid_inout,
                sizeof(pid_t));
        if(res) {
            return res;
        }
    }

    int exitcode;
    res = process_reap_child(process, to_reap_id, &exitcode, nowait);
    if(res) {
        return res;
    }

    res = process_write_usermem(
            process,
            user_exitcode,
            &exitcode,
            sizeof(int));
    if(res) {
        wprintk("sys_reap: Failed to copy process exitcode to userspace!\n");
        // We did reap the process,
        // but the user passed us an invalid location to write,
        // so for now we'll consider that a success and still return zero
    }

    return 0;
}

