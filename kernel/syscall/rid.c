
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

    // Only consider certain flags for selecting a value
    unsigned long select = flags & (RID_UID | RID_GID | RID_PID);

    id_t id;

    uid_t target_uid;
    gid_t target_gid;

    if(flags & RID_SELF)
    {
        target_pid = process_get_id(process);
        target_uid = process_get_uid(process);
        target_gid = process_get_gid(process);
    }
    else if(flags & RID_PARENT)
    {
        res = process_get_parent_id(process, &target_pid);
        if(res) {
            return res;
        }
        res = process_id_to_user_id(target_pid, &target_uid);
        if(res) {
            return res;
        }
        res = process_id_to_group_id(target_pid, &target_gid);
        if(res) {
            return res;
        }
    }
    else
    {
        if(!process_exists(target_pid)) {
            return -ENXIO;
        }
        res = process_id_to_user_id(target_pid, &target_uid);
        if(res) {
            return res;
        }
        res = process_id_to_group_id(target_pid, &target_gid);
        if(res) {
            return res;
        }
    }

    if(flags == (RID_UID | RID_GID)) {
        if(target_uid != target_gid) {
            return -EINVAL;
        }
        id = target_uid;
    }
    else if(flags == RID_UID) {
        id = target_uid;
    }
    else if(flags == RID_GID) {
        id = target_gid;
    }
    else if(flags == RID_PID) {
        id = target_pid;
    } else {
        return -EINVAL;
    }

    res = process_write_usermem(process, id_out, &id, sizeof(id));
    if(res) {
        return res;
    }

    return 0;
}

