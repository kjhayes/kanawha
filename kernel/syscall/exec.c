
#include <kanawha/assert.h>
#include <kanawha/printk.h>
#include <kanawha/proc/exec.h>
#include <kanawha/proc/process.h>
#include <kanawha/syscall.h>

#ifdef CONFIG_DEBUG_SYSCALL_EXEC
#define LOG(fmt, ...)                                                          \
    printk("PID(%ld) syscall_exec: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_exec(fd_t file, unsigned long exec_flags)
{
    int res;

    struct process *process = current_process();
    if(process == NULL)
    {
        return -EINVAL;
    }

    struct file *desc = file_table_get_file(process->file_table, process, file);

    if(desc == NULL)
    {
        fs_file_put(desc);
        return -EINVAL;
    }

    res = process_exec(process, desc, exec_flags);
    fs_file_put(desc);

    return res;
}
