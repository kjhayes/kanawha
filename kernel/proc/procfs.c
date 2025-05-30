
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/init.h>
#include <kanawha/proc/process.h>
#include <kanawha/string.h>

static DECLARE_SPINLOCK(procfs_lock);

static struct vfs_mount *procfs_mount = NULL;

static int
init_procfs_mount(void)
{
    int res;

    struct vfs_mount *mnt = vfs_mount_create();
    if(mnt == NULL) {
        return -ENOMEM;
    }

    procfs_mount = mnt;

    res = sysfs_register_mount(
            &procfs_mount->fs_mount,
            "proc");
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, init_procfs_mount, "Registering procfs Sysfs Mount");

static int
__procfs_read_user_id(
        unsigned long *out,
        void *state)
{
    struct process *proc = state;
    *out = process_get_uid(proc);
    return 0;
}

static int
__procfs_read_group_id(
        unsigned long *out,
        void *state)
{
    struct process *proc = state;
    *out = process_get_gid(proc);
    return 0;
}

static int
__procfs_read_parent_pid(
        unsigned long *out,
        void *state)
{
    struct process *proc = state;
    pid_t parent_id;
    process_get_parent_id(proc, &parent_id);
    *out = parent_id;
    return 0;
}

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
static ssize_t
__procfs_read_tracked_exec(
        size_t offset,
        char *buf,
        size_t buflen,
        void *state)
{
    struct process *proc = state;

    const char *exec = proc->tracked_exec;
    if(exec == NULL) {
        exec = "";
    }

    size_t len = strlen(exec);
    if(offset >= len) {
        return 0;
    }

    strncpy(buf, exec+offset, buflen);

    if((len-offset) < buflen) {
        return len-offset;
    } else {
        return buflen;
    }
}
#endif

int
procfs_register_process(
        struct process *process)
{
    int res;

    struct procfs_process_data *data = &process->procfs_data;

    char namebuf[64];
    snprintk(namebuf, 64, "proc%ld", (sl_t)process->id);
    namebuf[63] = '\0';

    data->vfs_struct_node = vfs_create_struct_node(procfs_mount, namebuf);
    if(data->vfs_struct_node == NULL) {
        return -ENOMEM;
    }

    res = vfs_struct_node_add_unsigned_long_field(
            data->vfs_struct_node,
            "uid",
            (void*)process,
            __procfs_read_user_id,
            NULL);
    if(res) {
        wprintk("Failed to register procfs \"uid\" node (err=%s)!\n",
                errnostr(res));
    }
    res = vfs_struct_node_add_unsigned_long_field(
            data->vfs_struct_node,
            "gid",
            (void*)process,
            __procfs_read_group_id,
            NULL);
    if(res) {
        wprintk("Failed to register procfs \"gid\" node (err=%s)!\n",
                errnostr(res));
    }
    res = vfs_struct_node_add_unsigned_long_field(
            data->vfs_struct_node,
            "parent",
            (void*)process,
            __procfs_read_parent_pid,
            NULL);
    if(res) {
        wprintk("Failed to register procfs \"parent\" node (err=%s)!\n",
                errnostr(res));
    }

#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    res = vfs_struct_node_add_buffer_field(
            data->vfs_struct_node,
            "exec",
            (void*)process,
            __procfs_read_tracked_exec,
            NULL);
    if(res) {
        wprintk("Failed to register procfs \"exec\" node (err=%s)!\n",
                errnostr(res));
    }
#endif

    return 0;
}

int
procfs_deregister_process(
        struct process *process)
{
    int res;

    struct procfs_process_data *data = &process->procfs_data;

    if(data->vfs_struct_node != NULL) {
        res = vfs_destroy_struct_node(data->vfs_struct_node);
        if(res) {
            return res;
        }
    }

    return 0;
}

