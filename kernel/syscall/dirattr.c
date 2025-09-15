
#include <kanawha/uapi/dir.h>
#include <kanawha/uapi/attr.h>
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>

#ifdef CONFIG_DEBUG_SYSCALL_DIRATTR
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_dirattr(
        fd_t dir_fd,
        int attr,
        size_t __user *user_value)
{
    int res;
    struct process *process = current_process();
    struct file *file =
        file_table_get_file(
                process->file_table,
                process,
                dir_fd);
    if(file == NULL) {
        return -EINVAL;
    }

    size_t value;
    res = direct_file_dir_readattr(
            file,
            attr,
            &value);
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

    res = process_write_usermem(
            process,
            user_value,
            &value,
            sizeof(size_t));
    if(res) {

    }
            
    return 0;
}

