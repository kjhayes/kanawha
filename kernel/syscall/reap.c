
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

    struct process *to_reap = NULL;

    if(flags & REAP_ANY) {
        // TODO
        res = process_get_reapable_child(
                process,
                nowait,
                &to_reap);
        if(res) {
            return res;
        }
    } else {
        pid_t to_reap_id;
        res = process_read_usermem(
                process,
                &to_reap_id,
                pid_inout,
                sizeof(pid_t));
        if(res) {
            return res;
        }

        to_reap = process_from_pid(to_reap_id);

        if(to_reap == NULL) {
            return -ENXIO;
        }

        if(to_reap->parent != process) {
            // Return -ENXIO to avoid leaking which PID's exist,
            // which PID's exist shouldn't need to be private but this adds
            // and additional level of difficulty for an attacker
            return -ENXIO;
        }
    }

    if(to_reap == NULL) {
        return -EINVAL;
    }

    int exitcode;
    res = process_reap(to_reap, &exitcode, nowait);
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

