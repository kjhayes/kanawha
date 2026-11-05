#ifndef __KANAWHA__PROC_PROCFS_H__
#define __KANAWHA__PROC_PROCFS_H__

#include <kanawha/sysfs/vfs.h>

struct procfs_process_data
{
    // TODO
};

int
procfs_register_process(struct process *process);
int
procfs_deregister_process(struct process *process);

#endif
