
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/fs/path.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/printk.h>

#ifdef CONFIG_DEBUG_SYSCALL_PIPE
#define LOG(fmt, ...) \
    printk("PID(%ld) syscall_pipe: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_pipe(
        unsigned long flags,
	    unsigned long mode_flags,
        fd_t __user *out)
{
    int res;

    struct process *process = current_process();

    if((mode_flags & FILE_MODE_OPEN_TRUNC)
     ||(mode_flags & FILE_MODE_WRITE_EXTEND))
    {
	return -EINVAL;
    }

    struct fs_path *pipe;

    LOG("flags=0x%lx\n",
            flags);

    res = fs_path_create_anon_pipe(&pipe);
    if(res) {
        LOG("Failed to create anonymous pipe: %s\n",
                errnostr(res));
        return res;
    }    

    fd_t fd;
    res = file_table_open_path(
            process->file_table,
            process,
            pipe,
            FILE_PERM_READ|FILE_PERM_WRITE,
            mode_flags,
            &fd);
    if(res) {
        fs_path_put(pipe);
        return res;
    }

    res = process_write_usermem(process, out, &fd, sizeof(fd_t));
    if(res) {
        file_table_close(
                process->file_table,
                process,
                fd);
        fs_path_put(pipe);
        return res;
    }

    fs_path_put(pipe);
    return 0;
}


