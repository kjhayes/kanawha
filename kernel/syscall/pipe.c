
#include <kanawha/fs/path.h>
#include <kanawha/printk.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/socket.h>
#include <kanawha/uapi/syscall.h>

#ifdef CONFIG_DEBUG_SYSCALL_PIPE
#define LOG(fmt, ...)                                                          \
    printk("PID(%ld) syscall_pipe: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_pipe(unsigned long flags, unsigned long mode_flags, fd_t __user *out)
{
    int res;

    struct process *process = current_process();

    if((mode_flags & FILE_MODE_OPEN_TRUNC) ||
       (mode_flags & FILE_MODE_WRITE_EXTEND))
    {
        return -EINVAL;
    }

    LOG("flags=0x%lx\n", flags);

    struct fs_node *pipe_node;
    pipe_node = pipe_create_anonymous();
    if(pipe_node == NULL)
    {
        LOG("Failed to create anonymous pipe!\n");
        return -ENOMEM;
    }

    struct fs_path *pipe_path;
    res = fs_path_create_anonymous(pipe_node, &pipe_path);
    if(res)
    {
        LOG("Failed to create anonymous pipe fs_path: %s\n", errnostr(res));
        return res;
    }
    fs_node_put(pipe_node);

    fd_t fd;
    res = file_table_open_path(process->file_table,
                               process,
                               pipe_path,
                               FILE_PERM_READ | FILE_PERM_WRITE,
                               mode_flags,
                               &fd);
    if(res)
    {
        fs_path_put(pipe_path);
        return res;
    }

    res = process_write_usermem(process, out, &fd, sizeof(fd_t));
    if(res)
    {
        file_table_close(process->file_table, process, fd);
        fs_path_put(pipe_path);
        return res;
    }

    fs_path_put(pipe_path);
    return 0;
}
