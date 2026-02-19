
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/fs/path.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/printk.h>
#include <kanawha/socket.h>

#ifdef CONFIG_DEBUG_SYSCALL_SOCKET
#define LOG(fmt, ...) \
    printk("PID(%ld) syscall_socket: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_socket(
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

    LOG("flags=0x%lx\n",
            flags);

    struct fs_node *socket_node;
    socket_node = socket_create_anonymous();
    if(socket_node == NULL) {
        LOG("Failed to create anonymous socket!\n");
        return -ENOMEM;
    }

    struct fs_path *socket_path;
    res = fs_path_create_anonymous(socket_node, &socket_path);
    if(res) {
        LOG("Failed to create anonymous socket fs_path: %s\n",
                errnostr(res));
        return res;
    }    
    fs_node_put(socket_node);

    fd_t fd;
    res = file_table_open_path(
            process->file_table,
            process,
            socket_path,
            0, // cannot read/write a socket
            mode_flags,
            &fd);
    if(res) {
        fs_path_put(socket_path);
        return res;
    }

    res = process_write_usermem(process, out, &fd, sizeof(fd_t));
    if(res) {
        file_table_close(
                process->file_table,
                process,
                fd);
        fs_path_put(socket_path);
        return res;
    }

    fs_path_put(socket_path);
    return 0;
}

