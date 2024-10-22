
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/fs/node.h>

#define SYSCALL_OPEN_MAX_PATH_LEN 256

int
syscall_open(
        struct process *process,
        const char __user *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        fd_t __user *fd)
{
    int res;

    size_t path_len;
    res = process_strlen_usermem(process, path, SYSCALL_OPEN_MAX_PATH_LEN+1, &path_len);
    if(res) {
        return res;
    }

    if(path_len > SYSCALL_OPEN_MAX_PATH_LEN) {
        // Path is too long
        dprintk("PID(%ld) syscall_open: path is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)path_len,
                (ull_t)SYSCALL_OPEN_MAX_PATH_LEN);
        return -EINVAL;
    }

    char path_buf[path_len + 1];

    res = process_read_usermem(
            process,
            (void*)path_buf,
            (void __user*)path,
            path_len);
    if(res) {
        dprintk("syscall_open: failed to read file path! process_read_usermem(%p) -> %s\n",
                path, errnostr(res));
        return res;
    }

    path_buf[path_len] = '\0';

#ifdef CONFIG_DEBUG_SYSCALL_OPEN
    printk("PID(%ld) syscall_open(path=%s, path_len=0x%llx, access_flags=0x%llx, mode_flags=0x%llx)\n",
            process->id, path_buf, path_len, (ull_t)access_flags, (ull_t)mode_flags);
#endif

    fd_t kernel_fd;
    res = file_table_open(
            process->file_table,
            process,
            path_buf,
            access_flags,
            mode_flags,
            &kernel_fd);
    if(res) {
        dprintk("PID(%ld) syscall_open: file_table_open(%s) returned %s\n",
                (sl_t)process->id, path_buf, errnostr(res));
        return res;
    }

    res = process_write_usermem(
            process,
            fd,
            &kernel_fd,
            sizeof(fd_t));
    if(res) {
        file_table_close(process->file_table, process, kernel_fd);
        return res;
    }

    if(mode_flags & FILE_MODE_OPEN_TRUNC) {
        struct file *file = file_table_get_file(
                process->file_table,
                process,
                kernel_fd);
        if(file == NULL) {
            dprintk("PID(%ld) syscall_open: Failed to open file for truncation! (err=%s)\n",
                    process->id, errnostr(res));
            file_table_close(process->file_table, process, kernel_fd);
            return res;
        }

        res = fs_node_setattr(
                file->path->fs_node,
                FS_NODE_ATTR_DATA_SIZE,
                0);
        if(res) {
            dprintk("PID(%ld) syscall_open: Failed to truncate file! (err=%s)\n",
                    process->id, errnostr(res));
            file_table_put_file(
                    process->file_table,
                    process,
                    file);
            file_table_close(process->file_table, process, kernel_fd);
            return res;
        }
    }

#ifdef CONFIG_DEBUG_SYSCALL_OPEN
    printk("PID(%ld) syscall_open: fd=%ld\n",
            (sl_t)process->id, (sl_t)kernel_fd);
#endif
    return 0;
}

