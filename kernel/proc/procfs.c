
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

static int
procfs_root_callback(
        struct vfs_printer_node *node,
        struct printer *printer)
{
    struct procfs_process_data *data =
        container_of(node, struct procfs_process_data, root_node);
    struct process *proc =
        container_of(data, struct process, procfs_data);
    dump_process(printer, proc);
    return 0;
}

int
procfs_register_process(struct process *process)
{
    int res;
    struct procfs_process_data *data = &process->procfs_data;

    data->name = fmt_kstrdup(KM_KERNEL, "proc%lu", (ul_t)process->id);
    if(data->name == NULL) {
        return -ENOMEM;
    }

    res = vfs_init_printer_node(
            &data->root_node,
            procfs_root_callback);
    if(res) {
        kfree(data->name);
        return res;
    }

    res = vfs_mount_insert_node_and_link_root(
            procfs_mount,
            vfs_printer_node_as_vfs_node(&data->root_node),
            data->name);
    if(res) {
        eprintk("procfs_register_process: vfs_mount_insert_node_and_link_root returned %e! (when registering \"%s\")",
                res, data->name);
        kfree(data->name);
        return res;
    }

    return 0;
}

int
procfs_deregister_process(struct process *process)
{
    int res;
    struct procfs_process_data *data = &process->procfs_data;

    res = vfs_mount_unlink_root(procfs_mount, data->name);
    if(res) {
        return res;
    }

    res = vfs_mount_remove_node(
            procfs_mount,
            vfs_printer_node_as_vfs_node(&data->root_node));
    if(res) {
        return res;
    }

    kfree(data->name);

    return 0;
}
