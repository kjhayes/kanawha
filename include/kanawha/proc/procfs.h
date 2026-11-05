#ifndef __KANAWHA__PROC_PROCFS_H__
#define __KANAWHA__PROC_PROCFS_H__

#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/vfs_printer.h>

struct procfs_process_data
{
    char *name;
    struct vfs_printer_node root_node;
    struct vfs_printer_node parent_node;
    struct vfs_printer_node exec_node;
    struct vfs_printer_node idle_node;
    struct vfs_printer_node name_node;
};

int
procfs_register_process(struct process *process);
int
procfs_deregister_process(struct process *process);

#endif
