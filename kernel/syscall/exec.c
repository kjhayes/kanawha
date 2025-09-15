
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
    struct process *process = current_process();
    if(process == NULL) {
	return -EINVAL;
    }

    LOG("exec(%ld) %s\n",
                file,
                desc == NULL ? "NULL" : name == NULL ? "UNNAMED" : name);

    return process_exec(
	    process,
	    file,
	    exec_flags);
}

