
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/syscall.h>
#include <kanawha/uapi/dir.h>

#ifdef CONFIG_DEBUG_SYSCALL_DIRBEGIN
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_dirbegin(fd_t dir_fd)
{
    int res;
    struct process *process = current_process();

    struct file *file =
        file_table_get_file(process->file_table, process, dir_fd);
    if(file == NULL)
    {
        return -EINVAL;
    }

    res = direct_file_dir_begin(file);
    if(res) {
        fs_file_put(file);
        return res;
    }

    fs_file_put(file);
    return 0;
}
