
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/uapi/poll.h>
#include <kanawha/waitqueue.h>
#include <kanawha/kmalloc.h>
#include <kanawha/uapi/syscall.h>

#define SOCKET_FS_PIPE_BUFLEN (0x100)

struct socket_fs_node
{
    struct fs_node *fs_node;
    struct ptree_node pnode;

    irq_lock_t lock;

    enum {
        SOCKET_FS_NODE_SOCKET,
        SOCKET_FS_NODE_PIPE,
    } type;

    union
    {
        struct
        {
            struct waitqueue pending_wq;
            struct waitqueue unpaired_wq;

            enum {
                SOCKET_STATUS_NONE,
                SOCKET_STATUS_WAITING_FOR_SERVER,
                SOCKET_STATUS_WAITING_FOR_CLIENT,
                SOCKET_STATUS_PAIRED,
            } status;

            int unpaired_result;
            size_t unpaired_inode;

        } socket;

        struct
        {
            struct waitqueue write_wq;
            struct waitqueue read_wq;

            size_t buflen;
            size_t head;
            size_t tail;
            char *buffer;

        } pipe;
    };
};

static inline void
socket_lock_acquire(
        struct socket_fs_node *socket)
{
    irq_lock_acquire(&socket->lock);
}
static inline void
socket_lock_release(
        struct socket_fs_node *socket)
{
    irq_lock_release(&socket->lock);
}

static struct socket_fs_mount
{
    struct fs_mount fs_mount;

    irq_lock_t inode_tree_lock;
    struct ptree inode_tree;

} socket_fs_mount;

static inline int
socket_fs_pipe_empty(
        struct socket_fs_node *socket)
{
    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_PIPE);
    return socket->pipe.head == socket->pipe.tail;
}

static inline int
socket_fs_pipe_full(
        struct socket_fs_node *socket)
{
    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_PIPE);
    return (((socket->pipe.head+1)%socket->pipe.buflen) == socket->pipe.tail);
}

static ssize_t 
socket_fs_pipe_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;
    dprintk("socket_fs_pipe_file_read\n");
    if(amount == 0) {
        return 0;
    }
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct socket_fs_node *socket = fs_node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(socket));
    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_PIPE);

    ssize_t read = 0;

    socket_lock_acquire(socket);

    DEBUG_ASSERT(KERNEL_ADDR(socket->pipe.buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(socket->pipe.buflen > socket->pipe.head);
    DEBUG_ASSERT(socket->pipe.buflen > socket->pipe.tail);

    while(read == 0) {

        // TODO: This loops once per byte which kind of sucks
        while(amount > 0 && !socket_fs_pipe_empty(socket)) {
            *(uint8_t*)buffer = ((uint8_t*)socket->pipe.buffer)[socket->pipe.tail];
            socket->pipe.tail = (socket->pipe.tail + 1) % socket->pipe.buflen;
            read += 1;
            amount--;
            buffer++;
        }

        if(read == 0) {
            int can_block = !(flags & FS_FILE_READ_NON_BLOCKING);
            if(can_block) {
                res = wait_on_irq_lock_release(&socket->pipe.read_wq, &socket->lock);
                if(res) {
                    return res;
                }
                socket_lock_acquire(socket);
            } else {
                if(read == 0) {
                    read = -EWOULDBLOCK;
                }
            }
        }
    }
 
    socket_lock_release(socket);
    if(read > 0) {
        wake_all(&socket->pipe.write_wq);
    }

    return read;
}

static ssize_t 
socket_fs_pipe_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;
    dprintk("socket_fs_pipe_file_write\n");
    if(amount == 0) {
        return 0;
    }
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct socket_fs_node *socket = fs_node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(socket));
    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_PIPE);

    ssize_t written = 0;

    socket_lock_acquire(socket);

    DEBUG_ASSERT(KERNEL_ADDR(socket->pipe.buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(socket->pipe.buflen > socket->pipe.head);
    DEBUG_ASSERT(socket->pipe.buflen > socket->pipe.tail);

    while(written == 0) {

        // TODO: This loops once per byte which kind of sucks
        while(amount > 0 && !socket_fs_pipe_full(socket)) {
            ((uint8_t*)socket->pipe.buffer)[socket->pipe.head] = *(uint8_t*)buffer;
            socket->pipe.head = (socket->pipe.head + 1) % socket->pipe.buflen;
            written += 1;
            amount--;
            buffer++;
        }

        if(written == 0) {
            int can_block = !(flags & FS_FILE_WRITE_NON_BLOCKING);
            if(can_block) {
                res = wait_on_irq_lock_release(&socket->pipe.write_wq, &socket->lock);
                if(res) {
                    return res;
                }
                socket_lock_acquire(socket);
            } else {
                if(written == 0) {
                    written = -EWOULDBLOCK;
                }
                break;
            }
        }
    }
 
    socket_lock_release(socket);
    if(written > 0) {
        wake_all(&socket->pipe.read_wq);
    }

    return written;
}

static int
socket_fs_pipe_file_poll(
        struct file *file,
        unsigned long watching,
        unsigned long *triggered_out)
{
    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct socket_fs_node *socket = node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(socket));

    socket_lock_acquire(socket);

    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_PIPE);

    unsigned long triggered = 0;

    if(watching & POLL_WRITE_NONBLOCKING) {
        if(!socket_fs_pipe_full(socket)) {
            triggered |= POLL_WRITE_NONBLOCKING;
        }
    }
    if(watching & POLL_READ_NONBLOCKING) {
        if(!socket_fs_pipe_empty(socket)) {
            triggered |= POLL_READ_NONBLOCKING;
        }
    }

    socket_lock_release(socket);

    *triggered_out = triggered;

    return 0;
}

static struct fs_node_ops
socket_fs_pipe_node_ops = {
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(socket_fs_pipe_node_ops);

static struct fs_file_ops
socket_fs_pipe_file_ops = {
    .read = socket_fs_pipe_file_read,
    .write = socket_fs_pipe_file_write,
    .poll = socket_fs_pipe_file_poll,

    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
};
FS_FILE_OPS_INIT_UNDEF(socket_fs_pipe_file_ops);

static int
socket_fs_mount_create_pipe(
        struct socket_fs_mount *mnt,
        size_t *inode_out);

static int
socket_fs_socket_node_form_connection(
        struct socket_fs_node *socket,
        int can_block,
        int is_client,
        size_t *inode_out)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(socket));
    DEBUG_ASSERT(socket->type == SOCKET_FS_NODE_SOCKET);

    int status_waiting_for_us = is_client
        ? SOCKET_STATUS_WAITING_FOR_CLIENT
        : SOCKET_STATUS_WAITING_FOR_SERVER;
    int status_waiting_for_other = is_client
        ? SOCKET_STATUS_WAITING_FOR_SERVER
        : SOCKET_STATUS_WAITING_FOR_CLIENT;

    struct socket_fs_mount *socket_mnt;
    socket_mnt = container_of(socket->fs_node->mount,
                              struct socket_fs_mount,
                              fs_mount);
    DEBUG_ASSERT(KERNEL_ADDR(socket_mnt));

    size_t inode = 0;

    socket_lock_acquire(socket);
    while(1) {
        if(socket->socket.status == SOCKET_STATUS_NONE)
        {
            if(!can_block) {
                res = -EWOULDBLOCK;
                break;
            }
            socket->socket.status = status_waiting_for_other;
            while(socket->socket.status == status_waiting_for_other) {
                res = wait_on_irq_lock_release(
                        &socket->socket.unpaired_wq,
                        &socket->lock);
                if(res) {
                    return res;
                }
                socket_lock_acquire(socket);
            }
            if(socket->socket.status == SOCKET_STATUS_PAIRED) {
                // We are done (grab the inode and result saved by
                // the other end of the connection)
                res = socket->socket.unpaired_result;
                inode = socket->socket.unpaired_inode;
                socket->socket.status = SOCKET_STATUS_NONE;
                wake_all(&socket->socket.pending_wq);
                break;
            } else {
                if(!can_block) {
                    res = -EWOULDBLOCK;
                    break;
                }
                // Try again?
                continue;
            }
        }
        else if((socket->socket.status == status_waiting_for_other)
             || (socket->socket.status == SOCKET_STATUS_PAIRED))
        {
            if(!can_block) {
                res = -EWOULDBLOCK;
                break;
            }
            // Put ourselves on the pending waitqueue and try again.
            res = wait_on_irq_lock_release(
                    &socket->socket.pending_wq,
                    &socket->lock);
            if(res) {
                return res;
            }
            socket_lock_acquire(socket);
            continue;
        }
        else if(socket->socket.status == status_waiting_for_us)
        {
            // We are the second to arrive.
            res = socket_fs_mount_create_pipe(
                    socket_mnt,
                    &inode);
            socket->socket.unpaired_inode = inode;
            socket->socket.unpaired_result = res;
            mbarrier();
            socket->socket.status = SOCKET_STATUS_PAIRED;
            wake_all(&socket->socket.unpaired_wq);
            break;
        }
    }
    socket_lock_release(socket);

    *inode_out = inode;
    return res;
}

static int
socket_fs_socket_node_accept(
        struct fs_node *fs_node,
        size_t *inode_out,
        unsigned long flags)
{
    struct socket_fs_node *socket = fs_node->backing.priv_state;
    int can_block = !(flags & FS_NODE_ACCEPT_NON_BLOCKING);
    return socket_fs_socket_node_form_connection(
            socket,
            can_block,
            0,
            inode_out);
}

static int
socket_fs_socket_node_connect(
        struct fs_node *fs_node,
        size_t *inode_out,
        unsigned long flags)
{
    struct socket_fs_node *socket = fs_node->backing.priv_state;
    int can_block = !(flags & FS_NODE_CONNECT_NON_BLOCKING);
    return socket_fs_socket_node_form_connection(
            socket,
            can_block,
            1,
            inode_out);
}

static struct fs_node_ops
socket_fs_socket_node_ops = {
    .accept = socket_fs_socket_node_accept,
    .connect = socket_fs_socket_node_connect,
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(socket_fs_socket_node_ops);

static struct fs_file_ops
socket_fs_socket_file_ops = {
    .flush = fs_file_nop_flush,
};
FS_FILE_OPS_INIT_UNDEF(socket_fs_socket_file_ops);

static int
socket_fs_mount_create_pipe(
        struct socket_fs_mount *mnt,
        size_t *inode_out)
{
    struct socket_fs_node *node = kzmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return -ENOMEM;
    }
    node->type = SOCKET_FS_NODE_PIPE;
    irq_lock_init(&node->lock);

    node->pipe.buflen = SOCKET_FS_PIPE_BUFLEN;
    node->pipe.head = 0;
    node->pipe.tail = 0;
    node->pipe.buffer = kzmalloc(node->pipe.buflen, KM_KERNEL);
    if(node->pipe.buffer == NULL) {
        kfree(node);
        return -ENOMEM;
    }
    waitqueue_init(&node->pipe.read_wq);
    waitqueue_name(&node->pipe.read_wq, "pipe-read");
    waitqueue_init(&node->pipe.write_wq);
    waitqueue_name(&node->pipe.write_wq, "pipe-write");

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_insert_any(&mnt->inode_tree, &node->pnode);
    irq_lock_release(&mnt->inode_tree_lock);

    *inode_out = node->pnode.key;

    return 0;
}
static int
socket_fs_mount_destroy_pipe(
        struct socket_fs_mount *mnt,
        struct socket_fs_node *node)
{
    waitqueue_deinit(&node->pipe.write_wq);
    waitqueue_deinit(&node->pipe.read_wq);

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_remove(&mnt->inode_tree, node->pnode.key);
    irq_lock_release(&mnt->inode_tree_lock);

    kfree(node->pipe.buffer);
    kfree(node);

    return 0;
}

static int
socket_fs_mount_create_socket(
        struct socket_fs_mount *mnt,
        size_t *inode_out)
{
    struct socket_fs_node *node = kzmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return -ENOMEM;
    }
    node->type = SOCKET_FS_NODE_SOCKET;
    irq_lock_init(&node->lock);

    waitqueue_init(&node->socket.pending_wq);
    waitqueue_name(&node->socket.pending_wq, "socket-pending");
    waitqueue_init(&node->socket.unpaired_wq);
    waitqueue_name(&node->socket.unpaired_wq, "socket-unpaired");

    node->socket.status = SOCKET_STATUS_NONE;
    node->socket.unpaired_result = 0;
    node->socket.unpaired_inode = 0;

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_insert_any(&mnt->inode_tree, &node->pnode);
    irq_lock_release(&mnt->inode_tree_lock);

    *inode_out = node->pnode.key;

    return 0;
}
static int
socket_fs_mount_destroy_socket(
        struct socket_fs_mount *mnt,
        struct socket_fs_node *node)
{
    waitqueue_deinit(&node->socket.pending_wq);
    waitqueue_deinit(&node->socket.unpaired_wq);

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_remove(&mnt->inode_tree, node->pnode.key);
    irq_lock_release(&mnt->inode_tree_lock);

    kfree(node);

    return 0;
}

static int
socket_fs_root_index(
        struct fs_mount *mnt,
        size_t *index)
{
    return -EINVAL;
}

static int
socket_fs_load_node(
        struct fs_mount *fs_mount,
        size_t index,
        struct fs_node *fs_node)
{
    struct socket_fs_mount *mnt;
    mnt = container_of(fs_mount, struct socket_fs_mount, fs_mount);
    irq_lock_acquire(&mnt->inode_tree_lock);
    struct ptree_node *pnode = ptree_get(&mnt->inode_tree, index);
    if(pnode == NULL) {
        irq_lock_release(&mnt->inode_tree_lock);
        return -ENXIO;
    }
    struct socket_fs_node *node;
    node = container_of(pnode, struct socket_fs_node, pnode);
    DEBUG_ASSERT(KERNEL_ADDR(fs_node));

    switch(node->type) {
        case SOCKET_FS_NODE_SOCKET:
            fs_node->backing.node_ops = &socket_fs_socket_node_ops;
            fs_node->backing.file_ops = &socket_fs_socket_file_ops;
            break;
        case SOCKET_FS_NODE_PIPE:
            fs_node->backing.node_ops = &socket_fs_pipe_node_ops;
            fs_node->backing.file_ops = &socket_fs_pipe_file_ops;
            break;
        default:
            irq_lock_release(&mnt->inode_tree_lock);
            return -EINVAL;
    }

    node->fs_node = fs_node;
    fs_node->backing.priv_state = node;

    irq_lock_release(&mnt->inode_tree_lock);
    return 0;
}

static int
socket_fs_unload_node(
        struct fs_mount *fs_mount,
        size_t index,
        struct fs_node *fs_node)
{
    int res;

    struct socket_fs_node *node = fs_node->backing.priv_state;
    DEBUG_ASSERT(node->fs_node == fs_node);
    DEBUG_ASSERT(node->pnode.key == index);

    struct socket_fs_mount *mnt;
    mnt = container_of(fs_mount, struct socket_fs_mount, fs_mount);

    switch(node->type) {
        case SOCKET_FS_NODE_SOCKET:
            res = socket_fs_mount_destroy_socket(mnt, node);
            if(res) {
                return res;
            }
            break;
        case SOCKET_FS_NODE_PIPE:
            res = socket_fs_mount_destroy_pipe(mnt, node);
            if(res) {
                return res;
            }
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static struct fs_mount_ops
socket_fs_mount_ops = {
    .root_index = socket_fs_root_index,
    .load_node = socket_fs_load_node,
    .unload_node = socket_fs_unload_node,
    .sync = fs_mount_nop_sync,
};

static int
socket_fs_mount_init(
        struct socket_fs_mount *mnt
        )
{
    int res;

    irq_lock_init(&mnt->inode_tree_lock);
    ptree_init(&mnt->inode_tree);

    res = init_fs_mount_struct(
            &mnt->fs_mount,
            &socket_fs_mount_ops);
    if(res) {
        return res;
    }

    return 0;
}

static int
init_socket_fs(void) {
    int res;
    res = socket_fs_mount_init(
            &socket_fs_mount);
    if(res) {
        return res;
    }
    return 0;
}
declare_init(fs, init_socket_fs);

struct fs_node *
socket_create_anonymous(void)
{
    int res;
    size_t inode;
    res = socket_fs_mount_create_socket(
            &socket_fs_mount,
            &inode);
    if(res) {
        return NULL;
    }
    struct fs_node *fs_node;
    fs_node = fs_mount_get_node(
            &socket_fs_mount.fs_mount,
            inode);
    return fs_node;
}

struct fs_node *
pipe_create_anonymous(void)
{
    int res;
    size_t inode;
    res = socket_fs_mount_create_pipe(
            &socket_fs_mount,
            &inode);
    if(res) {
        return NULL;
    }
    struct fs_node *fs_node;
    fs_node = fs_mount_get_node(
            &socket_fs_mount.fs_mount,
            inode);
    return fs_node;
}

