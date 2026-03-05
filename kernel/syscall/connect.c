
#include <kanawha/assert.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/syscall.h>
#include <kanawha/uapi/file.h>

int
syscall_connect(fd_t sock_fd, fd_t __user *connection, unsigned long flags)
{
    int res;

    struct process *process = current_process();

    struct file *sock_desc =
        file_table_get_file(process->file_table, process, sock_fd);
    if(sock_desc == NULL)
    {
        return -ENXIO;
    }

    struct fs_path *sock_path = sock_desc->path;
    struct fs_node *sock_node = fs_path_get_fs_node(sock_path);

    unsigned long connect_flags = 0;
    if(sock_desc->mode_flags & FILE_MODE_NON_BLOCK)
    {
        connect_flags |= FS_NODE_CONNECT_NON_BLOCKING;
    }

    size_t conn_inode;
    res = fs_node_connect(sock_node, &conn_inode, connect_flags);
    if(res)
    {
        file_table_put_file(process->file_table, process, sock_desc);
        return res;
    }

    struct fs_node *conn_node = fs_mount_get_node(sock_node->mount, conn_inode);
    // Close the file reference no matter what
    file_table_put_file(process->file_table, process, sock_desc);
    if(conn_node == NULL)
    {
        return -EINVAL;
    }

    fd_t conn_fd;
    res = file_table_open_node(process->file_table,
                               process,
                               conn_node,
                               FILE_PERM_READ | FILE_PERM_WRITE,
                               0,
                               &conn_fd);
    fs_node_put(conn_node);
    if(res)
    {
        return res;
    }

    res = process_write_usermem(process, connection, &conn_fd, sizeof(conn_fd));
    if(res)
    {
        file_table_close(process->file_table, process, conn_fd);
        return res;
    }

    return 0;
}
