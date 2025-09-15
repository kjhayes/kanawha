
#include <kanawha/syscall.h>
#include <kanawha/errno.h>

#ifdef CONFIG_DEBUG_SYSCALL_RID
#define LOG(fmt, ...) printk("PID(%ld) syscall_rid: " fmt, process_get_id(process), ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_rid(
        pid_t target_pid,
        unsigned long flags,
        id_t __user *id_out)
{
    int res;

    struct process *process = current_process();

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
            LOG("target process %ld does not exist!", (sl_t)target_pid);
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

    // Only consider certain flags for selecting a value
    unsigned long select = flags & (RID_UID | RID_GID | RID_PID);

    if(select == (RID_UID | RID_GID)) {
        if(target_uid != target_gid) {
            return -EINVAL;
        }
        id = target_uid;
    }
    else if(select == RID_UID) {
        id = target_uid;
    }
    else if(select == RID_GID) {
        id = target_gid;
    }
    else if(select == RID_PID) {
        id = target_pid;
    } else {
        LOG("invalid flags=0x%lx\n", flags);
        return -EINVAL;
    }

    LOG("writing ID(%lu) (flags=0x%lx)\n", id, flags);
    res = process_write_usermem(process, id_out, &id, sizeof(id));
    if(res) {
        LOG("write to usermem failed! (err=%s)\n", errnostr(res));
        return res;
    }

    return 0;
}

