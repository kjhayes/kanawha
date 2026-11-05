
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/proc/process.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

static struct vfs_mount *procfs_mount = NULL;

static int
init_procfs_mount(void)
{
    int res;

    struct vfs_mount *mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        return -ENOMEM;
    }

    procfs_mount = mnt;

    res = sysfs_register_mount(&procfs_mount->fs_mount, "proc");
    if(res)
    {
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, init_procfs_mount, "Registering procfs Sysfs Mount");

int
procfs_register_process(struct process *process)
{
    int res;
    struct procfs_process_data *data = &process->procfs_data;

    // TODO

    return 0;
}

int
procfs_deregister_process(struct process *process)
{
    int res;
    struct procfs_process_data *data = &process->procfs_data;

    // TODO

    return 0;
}
