
#include <kanawha/syscall.h>
#include <kanawha/errno.h>
#include <kanawha/proc/process.h>

int
syscall_wid(
        pid_t target_pid,
        unsigned long flags,
        id_t id)
{ 
    struct process *process = current_process();

    struct process *target;
    if(flags & WID_SELF) {
        target = process;
    } else {
        // We do not support reading the ID of other processes for now...
        // (or possibly ever, this is probably a bad idea)
        if(!process_is_root(process)) {
            return -EPERM;
        }
        return -EUNIMPL;
    }

    if(target == NULL) {
        return -ENXIO;
    }

    if(!process_is_root(process)) {
        return -EPERM;
    }

    if(flags & WID_UID) {
        target->user_id = id;
    }
    if(flags & WID_GID) {
        target->group_id = id;
    }

    return 0;
}

