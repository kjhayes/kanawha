
#include <kanawha/process.h>

int
syscall_reap(
        struct process *process,
        pid_t to_reap_id,
        unsigned long flags,
        int __user *user_exitcode)
{
    int res;

    struct process *to_reap = 
        process_from_pid(to_reap_id);

    if(to_reap == NULL) {
        return -ENXIO;
    }

    if(to_reap->parent != process) {
        // Return -ENXIO to avoid leaking which PID's exist,
        // which PID's exist shouldn't need to be private but this adds
        // and additional level of difficulty for an attacker
        return -ENXIO;
    }

    int exitcode;
    res = process_reap(to_reap, &exitcode);
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

