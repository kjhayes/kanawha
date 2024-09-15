
#include <kanawha/uapi/dir.h>
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>

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

int
syscall_dirattr(
        struct process *process,
        fd_t dir_fd,
        int attr,
        size_t __user *user_value)
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

#define SYSCALL_DIRNAME_MAX_NAME_LEN 128

int
syscall_dirname(
        struct process *process,
        fd_t dir_fd,
        char __user *user_namebuf,
        size_t user_namebuflen)
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

    size_t buf_len = user_namebuflen < SYSCALL_DIRNAME_MAX_NAME_LEN 
        ? user_namebuflen : SYSCALL_DIRNAME_MAX_NAME_LEN;

    char * name_buf = kmalloc(buf_len);
    if(name_buf == NULL) {
        file_table_put_file(
                process->file_table,
                process,
                file);
        return -ENOMEM;
    }

    res = direct_file_dir_readname(
            file,
            name_buf,
            buf_len);
    if(res) {
        kfree(name_buf);
        file_table_put_file(
                process->file_table,
                process,
                file);
        return res;
    }

    name_buf[buf_len-1] = '\0';

    res = file_table_put_file(
                process->file_table,
                process,
                file);
    if(res) {
        kfree(name_buf);
        return res;
    }

    res = process_write_usermem(
            process,
            user_namebuf,
            name_buf,
            buf_len);
    if(res) {
        kfree(name_buf);
        return res;
    }
           
    kfree(name_buf);
    return 0;
}
