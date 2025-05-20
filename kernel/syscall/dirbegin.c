
#include <kanawha/uapi/dir.h>
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>

#ifdef CONFIG_DEBUG_SYSCALL_DIRBEGIN
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_dirbegin(
        struct process *process,
        fd_t dir_fd)
{
    int res;
    struct file *file =
        file_table_get_file(
                process->file_table,
                process,
                dir_fd);
    if(file == NULL) {
        return -EINVAL;
    }

    LOG("PID(%ld): dirbegin (%s)\n",
            process->id,
            file->path->name);

    res = direct_file_dir_begin(file);
    if(res) {
        file_table_put_file(
                process->file_table,
                process,
                file);
        return res;
    }

    res = file_table_put_file(
            process->file_table,
            process,
            file);
    if(res) {
        return res;
    }

    return 0;
}

