
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

int
procfs_register_process(
        struct process *process)
{
    struct procfs_process_data *data = &process->procfs_data;

    char namebuf[64];
    snprintk(namebuf, 64, "proc%ld", (sl_t)process->id);
    namebuf[63] = '\0';

    data->vfs_struct_node = vfs_create_struct_node(procfs_mount, namebuf);
    if(data->vfs_struct_node == NULL) {
        return -ENOMEM;
    }

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

