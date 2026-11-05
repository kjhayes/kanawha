
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/proc/process.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

static struct vfs_mount *procfs_mount = NULL;

static int
procfs_parent_callback(
        struct process *process,
        struct printer *printer)
{
    int res;
    pid_t pid;
    res = process_get_parent_id(process, &pid);
    if(res) {
        return res;
    }
    fmt_print(printer, "%ld", (sl_t)pid);
    return 0;
}

static int
procfs_exec_callback(
        struct process *process,
        struct printer *printer)
{
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
    const char *exec = process->tracked_exec;
    fmt_print(printer, "%s\n", exec == NULL ? "" : exec);
#endif
    return 0;
}

static int
procfs_idle_callback(
        struct process *process,
        struct printer *printer)
{
    ssize_t percent = 100 - thread_running_percentage(&process->thread);
    fmt_print(printer, "%ld\n", (sl_t)percent);
    return 0;
}

static int
procfs_name_callback(
        struct process *process,
        struct printer *printer)
{
    const char *name = process_get_self_name(process);
    fmt_print(printer, "%s\n", name == NULL ? "" : name);
    return 0;
}

// __NAME, __FIELD, __CALLBACK
#define PROCFS_FIELD_XLIST(X,...)\
X(parent, parent_node, procfs_parent_callback, ##__VA_ARGS__)\
X(exec,   exec_node,   procfs_exec_callback, ##__VA_ARGS__)\
X(idle,   idle_node,   procfs_idle_callback, ##__VA_ARGS__)\
X(name,   name_node,   procfs_name_callback, ##__VA_ARGS__)\

/*
 * Above was pretty because
 * Below there be dragons
 * (X-Macro Expansions)
 */

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

#define XCASE(__NAME, __FIELD, __CALLBACK)\
static int \
__procfs_vfs_printer_callback__##__CALLBACK(\
        struct vfs_printer_node *node,\
        struct printer *printer)\
{\
    int res;\
    struct procfs_process_data *data =\
        container_of(node, struct procfs_process_data, __FIELD);\
    struct process *proc =\
        container_of(data, struct process, procfs_data);\
    return __CALLBACK(proc, printer);\
}
PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

int
procfs_register_process(struct process *process)
{
    int res;

    struct procfs_process_data *data = &process->procfs_data;

    data->name = NULL;
    unsigned int root_init = 0;
#define XCASE(__NAME, __FIELD, __CALLBACK, ...)\
    unsigned int __NAME##_init = 0;
    PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

    data->name = fmt_kstrdup(KM_KERNEL, "%lu", (ul_t)process->id);
    if(data->name == NULL) {
        res = -ENOMEM;
        goto err;
    }

    res = vfs_init_printer_node(
            &data->root_node,
            procfs_root_callback);
    if(res) {
        goto err;
    }

#define XCASE(__NAME, __FIELD, __CALLBACK, ...)\
    res = vfs_init_printer_node(\
            &data->__FIELD,\
            __procfs_vfs_printer_callback__##__CALLBACK);\
    if(res) {\
        goto err;\
    }
    PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

    res = vfs_mount_insert_node_and_link_root(
            procfs_mount,
            vfs_printer_node_as_vfs_node(&data->root_node),
            data->name);
    if(res) {
        goto err;
    }
    root_init = 1;

#define XCASE(__NAME, __FIELD, __CALLBACK, ...)\
    res = vfs_mount_insert_and_link(\
            procfs_mount,\
            vfs_printer_node_as_vfs_node(&data->__FIELD),\
            #__NAME,\
            vfs_printer_node_as_vfs_node(&data->root_node));\
    if(res) {\
        goto err;\
    }\
    __NAME##_init = 1;
    PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

    return 0;

err:
    if(root_init) {
        vfs_mount_unlink_root(procfs_mount, data->name);
        vfs_mount_remove_node(procfs_mount,
                vfs_printer_node_as_vfs_node(&data->root_node));
    }

#define XCASE(__NAME, __FIELD, __CALLBACK, ...)\
    if(__NAME##_init) {\
        vfs_mount_remove_node(procfs_mount,\
                vfs_printer_node_as_vfs_node(&data->__FIELD));\
    }
    PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

    kfree(data->name);
    return res;
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

#define XCASE(__NAME, __FIELD, __CALLBACK)\
    res = vfs_mount_remove_node(\
            procfs_mount,\
            vfs_printer_node_as_vfs_node(&data->__FIELD));\
    if(res) {\
        return res;\
    }
    PROCFS_FIELD_XLIST(XCASE)
#undef XCASE

    kfree(data->name);

    return 0;
}
