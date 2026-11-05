
#include <kanawha/assert.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/syscall.h>
#include <kanawha/uapi/file.h>

int
syscall_connect(fd_t sock_fd, fd_t __user *conn, unsigned long flags)
{
    int res;

    struct process *process = current_process();

    struct file *sock_desc =
        file_table_get_file(process->file_table, process, sock_fd);
    if(sock_desc == NULL)
    {
        return -ENXIO;
    }

    unsigned long connect_flags = 0;
    unsigned long mflags = fs_file_get_mode_flags(sock_desc);
    if(mflags & FILE_MODE_NON_BLOCK)
    {
        connect_flags |= FS_NODE_CONNECT_NON_BLOCKING;
    }

    struct fs_node *sock_node = fs_file_get_node(sock_desc);
    fs_file_put(sock_desc);
    if(sock_node == NULL) {
        return -EINVAL;
    }

    size_t conn_inode;
    res = fs_node_connect(sock_node, &conn_inode, connect_flags);
    if(res)
    {
        fs_node_put(sock_node);
        return res;
    }

    struct fs_node *conn_node = fs_mount_get_node(sock_node->mount, conn_inode);
    if(conn_node == NULL)
    {
        fs_node_put(sock_node);
        return -EINVAL;
    }

    fs_node_put(sock_node);

    fd_t conn_fd;
    res = file_table_open_node(process->file_table,
                               process,
                               conn_node,
                               FILE_PERM_READ | FILE_PERM_WRITE,
                               0,
                               FILE_INTERNAL_FLAG_CLIENT,
                               &conn_fd);
    if(res)
    {
        fs_node_put(conn_node);
        return res;
    }

    fs_node_put(conn_node);

    res = process_write_usermem(process, conn, &conn_fd, sizeof(conn_fd));
    if(res)
    {
        file_table_close(process->file_table, process, conn_fd);
        return res;
    }

    return 0;
}
