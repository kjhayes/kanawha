#ifndef __KANAWHA__PROCESS_EXEC_H__
#define __KANAWHA__PROCESS_EXEC_H__

#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>

int
process_exec(
	struct process *process,
    struct file *desc,
    unsigned long exec_flags);

#endif
