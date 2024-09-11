
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>

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
        eprintk("PID(%ld) syscall_open: path is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)path_len,
                (ull_t)SYSCALL_OPEN_MAX_PATH_LEN);
        return -EINVAL;
    }

    char path_buf[path_len + 1];

    dprintk("syscall_open(parent=%ld, path=%p, path_len=0x%llx, access_flags=0x%llx, mode_flags=0x%llx\n",
            (sl_t)parent_fd, path, (ull_t)path_len, (ull_t)access_flags, (ull_t)mode_flags);
    res = process_read_usermem(
            process,
            (void*)path_buf,
            (void __user*)path,
            path_len);
    if(res) {
        eprintk("syscall_open: failed to read file path! process_read_usermem(%p) -> %s\n",
                path, errnostr(res));
        return res;
    }

    path_buf[path_len] = '\0';

#ifdef CONFIG_DEBUG_SYSCALL_OPEN
    printk("PID(%ld) syscall_open(%s)\n",
            (sl_t)process->id, path_buf);
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
        eprintk("PID(%ld) syscall_open: file_table_open(%s) returned %s\n",
                (sl_t)process->id, path_buf, errnostr(res));
        return res;
    }

    res = process_write_usermem(
            process,
            fd,
            &kernel_fd,
            sizeof(fd_t));
    if(res) {
        return res;
    }

#ifdef CONFIG_DEBUG_SYSCALL_OPEN
    printk("PID(%ld) syscall_open: fd=%ld\n",
            (sl_t)process->id, (sl_t)kernel_fd);
#endif
    return 0;
}

