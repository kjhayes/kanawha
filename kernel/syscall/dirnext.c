#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>

#ifdef CONFIG_DEBUG_SYSCALL_DIRNEXT
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_dirnext(
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

#ifdef CONFIG_DEBUG_SYSCALL_DIRNEXT

    const char *__pathname = fs_path_get_name(file->path);
    LOG("PID(%ld) dirnext: (%s)\n",
            process->id,
            __pathname ? __pathname : "NULL");

#endif

    res = direct_file_dir_next(file);
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

