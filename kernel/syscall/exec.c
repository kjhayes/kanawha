
#include <kanawha/syscall.h>
#include <kanawha/printk.h>
#include <kanawha/assert.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/exec.h>

#ifdef CONFIG_DEBUG_SYSCALL_EXEC
#define LOG(fmt, ...) printk("PID(%ld) syscall_exec: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_exec(
	fd_t file,
	unsigned long exec_flags)
{
    int res;

    struct process *process = current_process();
    if(process == NULL) {
	return -EINVAL;
    }

    struct file *desc =
        file_table_get_file(process->file_table, process, file);
 
    if(desc == NULL) {
        file_table_put_file(process->file_table, process, desc);
        return -EINVAL;
    }

    LOG("exec(%ld -> \"%s\")\n", file, fs_path_get_name(desc->path));

    res = process_exec(
	    process,
	    desc,
	    exec_flags);

    file_table_put_file(process->file_table, process, desc);
    return res;
}

