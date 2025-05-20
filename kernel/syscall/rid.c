
#include <kanawha/syscall.h>
#include <kanawha/errno.h>

int
syscall_rid(
        struct process *process,
        pid_t target_pid,
        unsigned long flags,
        id_t __user *id_out)
{
    int res;

    struct process *target;
    if(flags & RID_SELF) {
        target = process;
    } else {
        // We do not support reading the ID of other processes for now...
        return -EUNIMPL;
    }

    if(target == NULL) {
        return -ENXIO;
    }

    id_t id;

    if((flags & RID_UID) && (flags & RID_GID)) {
        if(target->user_id != target->group_id) {
            return -EINVAL;
        }
        id = target->user_id;
    }
    else if(flags & RID_UID) {
        id = target->user_id;
    }
    else if(flags & RID_GID) {
        id = target->group_id;
    }

    res = process_write_usermem(process, id_out, &id, sizeof(id));
    if(res) {
        return res;
    }

    return 0;
}

