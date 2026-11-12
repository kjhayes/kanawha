
#include <kanawha/pipe/pipe.h>
#include <kanawha/ringbuf.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/uapi/poll.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/waitqueue.h>

#define PIPE_RINGBUF_LEN (0x100)

struct pipe_fs_node;

static int
pipe_fs_buffer_ensure_primary_inited(
        struct pipe_fs_buffer *buffer);
static int
pipe_fs_buffer_ensure_secondary_inited(
        struct pipe_fs_buffer *buffer);

struct pipe_page
{
    void __phys *addr;
    struct ptree_node ptree_node;
};

static struct pipe_fs_mount
{
    struct fs_mount fs_mount;

    irq_lock_t inode_tree_lock;
    struct ptree inode_tree;

} pipe_fs_mount;

static ssize_t
pipe_fs_buffer_file_read(struct file *file,
                         void *data,
                         ssize_t amount,
                         unsigned long flags)
{
    int res;
    dprintk("pipe_fs_buffer_file_read\n");
    if(amount == 0)
    {
        return 0;
    }
    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = fs_node->backing.priv_state;
    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    ssize_t read = 0;

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    if(buffer == NULL) {
        pipe_lock_release(pipe);
        return -EINVAL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(data));

    struct ringbuf *ringbuf;
    struct waitqueue *wait_on_wq;
    struct waitqueue *wake_wq;

    unsigned long iflags = fs_file_get_internal_flags(file);

    if(!(iflags & FILE_INTERNAL_FLAG_CLIENT))
    {
        // We are a server or a simple pipe...
        res = pipe_fs_buffer_ensure_primary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(fs_node);
            return res;
        }
        ringbuf = &buffer->primary_ringbuf;
        wait_on_wq = &buffer->primary_read_wq;
        wake_wq = &buffer->primary_write_wq;
    }
    else
    {
        // We are a client...
        res = pipe_fs_buffer_ensure_secondary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(fs_node);
            return res;
        }
        ringbuf = &buffer->secondary_ringbuf;
        wait_on_wq = &buffer->secondary_read_wq;
        wake_wq = &buffer->secondary_write_wq;
    }

    while(read == 0 && amount > 0)
    {
        ssize_t cur_read = ringbuf_read(ringbuf, data, amount);
        amount -= cur_read;
        data += cur_read;
        read += cur_read;

        if(read == 0)
        {
            // Checking if we should declare EOF
            int can_eof = 0;
            if(iflags & FILE_INTERNAL_FLAG_SERVER)
            {
                if(buffer->num_clients <= 0)
                {
                    can_eof = 1;
                }
            }
            else if(iflags & FILE_INTERNAL_FLAG_CLIENT)
            {
                if(buffer->num_servers <= 0)
                {
                    can_eof = 1;
                }
            }
            else
            {
                if(buffer->num_writers <= 0)
                {
                    can_eof = 1;
                }
            }

            if(can_eof)
            {
                pipe_lock_release(pipe);
                fs_node_put(fs_node);
                // We read nothing, and there is no one
                // else connected to this pipe to possibly
                // provide more data...
                return 0;
            }

            int can_block = !(flags & FS_FILE_READ_NON_BLOCKING);
            if(can_block)
            {
                int irq_flags;
                res = wait_on_irq_lock_release(wait_on_wq,
                                               &pipe->lock,
                                               &irq_flags);
                enable_restore_irqs(irq_flags);
                if(res)
                {
                    fs_node_put(fs_node);
                    return res;
                }
                // We could be interrupted here...
                pipe_lock_acquire(pipe);
            }
            else
            {
                if(read == 0)
                {
                    read = -EWOULDBLOCK;
                }
            }
        }
    }

    pipe_lock_release(pipe);
    if(read > 0)
    {
        wake_all(wake_wq);
    }

    fs_node_put(fs_node);
    return read;
}

static ssize_t
pipe_fs_buffer_file_write(struct file *file,
                          void *data,
                          ssize_t amount,
                          unsigned long flags)
{
    int res;
    dprintk("pipe_fs_buffer_file_write\n");
    if(amount == 0)
    {
        return 0;
    }
    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = fs_node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    ssize_t written = 0;

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    DEBUG_ASSERT(KERNEL_ADDR(data));

    unsigned long iflags = fs_file_get_internal_flags(file);

    struct ringbuf *ringbuf;
    struct waitqueue *wait_on_wq;
    struct waitqueue *wake_wq;

    if(!(iflags & FILE_INTERNAL_FLAG_SERVER))
    {
        // We are a client or a simple pipe
        res = pipe_fs_buffer_ensure_primary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(fs_node);
            return res;
        }
        ringbuf = &buffer->primary_ringbuf;
        wait_on_wq = &buffer->primary_write_wq;
        wake_wq = &buffer->primary_read_wq;
    }
    else
    {
        // We are a server...
        res = pipe_fs_buffer_ensure_secondary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(fs_node);
            return res;
        }
        ringbuf = &buffer->secondary_ringbuf;
        wait_on_wq = &buffer->secondary_write_wq;
        wake_wq = &buffer->secondary_read_wq;
    }

    while(written == 0 && amount > 0)
    {
        // Checking if we should declare EOF
        int can_eof = 0;
        if(iflags & FILE_INTERNAL_FLAG_SERVER)
        {
            if(buffer->num_clients <= 0)
            {
                can_eof = 1;
            }
        }
        else if(iflags & FILE_INTERNAL_FLAG_CLIENT)
        {
            if(buffer->num_servers <= 0)
            {
                can_eof = 1;
            }
        }
        else
        {
            if(buffer->num_readers <= 0)
            {
                can_eof = 1;
            }
        }

        if(can_eof)
        {
            pipe_lock_release(pipe);
            fs_node_put(fs_node);
            // If no one is connected, there is no point
            // in writing anything in the first place.
            return 0;
        }

        ssize_t cur_written = ringbuf_write(ringbuf, data, amount);
        amount -= cur_written;
        data += cur_written;
        written += cur_written;

        if(written == 0)
        {
            int can_block = !(flags & FS_FILE_WRITE_NON_BLOCKING);
            if(can_block)
            {
                int irq_flags;
                res = wait_on_irq_lock_release(wait_on_wq,
                                               &pipe->lock,
                                               &irq_flags);
                enable_restore_irqs(irq_flags);
                if(res)
                {
                    fs_node_put(fs_node);
                    return res;
                }
                // We could be interrupted here...
                pipe_lock_acquire(pipe);
            }
            else
            {
                if(written == 0)
                {
                    written = -EWOULDBLOCK;
                }
                break;
            }
        }
    }

    pipe_lock_release(pipe);
    if(written > 0)
    {
        wake_all(wake_wq);
    }
    fs_node_put(fs_node);

    return written;
}

static int
pipe_fs_buffer_file_poll(struct file *file,
                         unsigned long watching,
                         unsigned long *triggered_out)
{
    int res;

    struct fs_node *node = fs_file_get_node(file);
    if(node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    unsigned long iflags = fs_file_get_internal_flags(file);

    unsigned long triggered = 0;

    struct ringbuf *read_ringbuf;
    struct ringbuf *write_ringbuf;

    if(iflags & FILE_INTERNAL_FLAG_SERVER)
    {
        res = pipe_fs_buffer_ensure_primary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(node);
            return res;
        }
        res = pipe_fs_buffer_ensure_secondary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(node);
            return res;
        }
        read_ringbuf = &buffer->secondary_ringbuf;
        write_ringbuf = &buffer->primary_ringbuf;
    }
    else if(iflags & FILE_INTERNAL_FLAG_SERVER)
    {
        res = pipe_fs_buffer_ensure_primary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(node);
            return res;
        }
        res = pipe_fs_buffer_ensure_secondary_inited(buffer);
        if(res)
        {
            pipe_lock_release(pipe);
            fs_node_put(node);
            return res;
        }
        read_ringbuf = &buffer->primary_ringbuf;
        write_ringbuf = &buffer->secondary_ringbuf;
    }
    else
    {
        pipe_fs_buffer_ensure_primary_inited(buffer);
        read_ringbuf = &buffer->primary_ringbuf;
        write_ringbuf = &buffer->primary_ringbuf;
    }

    if(watching & POLL_WRITE_NONBLOCKING)
    {
        if(!ringbuf_full(write_ringbuf))
        {
            triggered |= POLL_WRITE_NONBLOCKING;
        }
    }
    if(watching & POLL_READ_NONBLOCKING)
    {
        if(!ringbuf_empty(read_ringbuf))
        {
            triggered |= POLL_READ_NONBLOCKING;
        }
    }

    pipe_lock_release(pipe);
    fs_node_put(node);

    *triggered_out = triggered;

    return 0;
}

static int
pipe_fs_buffer_file_status(struct file *file,
                           unsigned long type,
                           unsigned long *value)
{
    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = fs_node->backing.priv_state;

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    switch(type)
    {
    case FILE_STATUS_CONNECTED:
    {
        unsigned long iflags = fs_file_get_internal_flags(file);
        if(iflags & FILE_INTERNAL_FLAG_SERVER)
        {
            *value = buffer->num_clients > 0;
        }
        else if(iflags & FILE_INTERNAL_FLAG_CLIENT)
        {
            *value = buffer->num_servers > 0;
        }
        else
        {
            int other = 0;
            unsigned long aflags = fs_file_get_access_flags(file);
            if(aflags & FILE_PERM_READ)
            {
                other |= buffer->num_writers > 0;
            }
            if(aflags & FILE_PERM_WRITE)
            {
                other |= buffer->num_readers > 0;
            }
            *value = other;
        }
        break;
    }
    default:
        pipe_lock_release(pipe);
        fs_node_put(fs_node);
        return -EINVAL;
    }

    pipe_lock_release(pipe);
    fs_node_put(fs_node);

    return 0;
}

static int
pipe_fs_buffer_node_load_page(struct fs_node *node,
                              uintptr_t pfn,
                              unsigned long flags,
                              void __phys **addr)
{
    int res;

    struct pipe_fs_node *pipe = node->backing.priv_state;
    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    irq_lock_acquire(&buffer->page_tree_lock);
    struct pipe_page *pg;
    {
        struct ptree_node *pnode = ptree_get(&buffer->page_tree, pfn);
        if(pnode == NULL)
        {
            pg = kmalloc(sizeof(*pg), KM_KERNEL);
            if(pg == NULL)
            {
                irq_lock_release(&buffer->page_tree_lock);
                return -ENOMEM;
            }

            res = page_alloc(VMEM_MIN_PAGE_ORDER, &pg->addr, PAGE_ALLOC_64BIT);
            if(res)
            {
                irq_lock_release(&buffer->page_tree_lock);
                kfree(pg);
                return res;
            }
            memset_p(pg->addr, 0, 1ULL << VMEM_MIN_PAGE_ORDER);

            ptree_insert(&buffer->page_tree, &pg->ptree_node, pfn);
        }
        else
        {
            pg = container_of(pnode, struct pipe_page, ptree_node);
        }
    }
    *addr = pg->addr;
    irq_lock_release(&buffer->page_tree_lock);

    return 0;
}

static int
pipe_fs_buffer_node_unload_page(struct fs_node *node,
                                uintptr_t pfn,
                                unsigned long flags,
                                void __phys *addr)
{
    int res;
    return 0;
}

static int
pipe_fs_buffer_node_getattr(struct fs_node *node, int attr, size_t *value)
{
    switch(attr)
    {
    case FS_NODE_ATTR_PAGE_ORDER:
        *value = VMEM_MIN_PAGE_ORDER;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static int
pipe_fs_buffer_file_on_open(struct file *file)
{
    struct fs_node *node = fs_file_get_node(file);
    if(node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = node->backing.priv_state;
    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    unsigned long aflags = fs_file_get_access_flags(file);
    unsigned long iflags = fs_file_get_internal_flags(file);

    if(aflags & FILE_PERM_WRITE)
    {
        buffer->num_writers++;
    }
    if(aflags & FILE_PERM_READ)
    {
        buffer->num_readers++;
    }
    if(iflags & FILE_INTERNAL_FLAG_CLIENT)
    {
        buffer->num_clients++;
    }
    if(iflags & FILE_INTERNAL_FLAG_SERVER)
    {
        buffer->num_servers++;
    }

    dprintk(
        "pipe_fs_buffer_file_on_open: pipe(%ld) clients(%ld) servers(%ld)\n",
        (sl_t)pipe->pnode.key,
        (sl_t)buffer->num_clients,
        (sl_t)buffer->num_servers);

    pipe_lock_release(pipe);
    fs_node_put(node);

    return 0;
}

static int
pipe_fs_buffer_file_on_close(struct file *file)
{
    struct fs_node *node = fs_file_get_node(file);
    if(node == NULL)
    {
        return -ENXIO;
    }
    struct pipe_fs_node *pipe = node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));

    pipe_lock_acquire(pipe);

    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    unsigned long aflags = fs_file_get_access_flags(file);
    unsigned long iflags = fs_file_get_internal_flags(file);

    // If the final client/server disconnects, we need
    // to wake all of the opposite side which may be sleeping
    // (they should now read/write EOF instead of blocking)
    int wake_all_servers = 0;
    int wake_all_clients = 0;
    int wake_all_readers = 0;
    int wake_all_writers = 0;


    if(aflags & FILE_PERM_WRITE)
    {
        DEBUG_ASSERT(buffer->num_writers > 0);
        buffer->num_writers--;
        if(buffer->num_writers == 0)
        {
            wake_all_readers = 1;
        }
    }
    if(aflags & FILE_PERM_READ)
    {
        DEBUG_ASSERT(buffer->num_readers > 0);
        buffer->num_readers--;
        if(buffer->num_readers == 0)
        {
            wake_all_writers = 1;
        }
    }
    if(iflags & FILE_INTERNAL_FLAG_CLIENT)
    {
        DEBUG_ASSERT(buffer->num_clients > 0);
        buffer->num_clients--;
        if(buffer->num_clients == 0)
        {
            wake_all_servers = 1;
        }
    }
    if(iflags & FILE_INTERNAL_FLAG_SERVER)
    {
        DEBUG_ASSERT(buffer->num_servers > 0);
        buffer->num_servers--;
        if(buffer->num_servers == 0)
        {
            wake_all_clients = 1;
        }
    }

    if(wake_all_clients && buffer->num_clients > 0)
    {
        printk("pipe: waking all clients!\n");
        if(buffer->primary_inited)
        {
            wake_all(&buffer->primary_write_wq);
        }
        if(buffer->secondary_inited)
        {
            wake_all(&buffer->secondary_read_wq);
        }
    }
    if(wake_all_servers && buffer->num_servers > 0)
    {
        printk("pipe: waking all servers!\n");
        if(buffer->secondary_inited)
        {
            wake_all(&buffer->secondary_write_wq);
        }
        if(buffer->primary_inited)
        {
            wake_all(&buffer->primary_read_wq);
        }
    }

    // TODO do not issue more than one "wake" to
    // the same waitqueue...
    if(wake_all_readers)
    {
        if(buffer->primary_inited)
        {
            wake_all(&buffer->primary_read_wq);
        }
        if(buffer->secondary_inited)
        {
            wake_all(&buffer->secondary_read_wq);
        }
    }
    if(wake_all_writers)
    {
        if(buffer->primary_inited)
        {
            wake_all(&buffer->primary_write_wq);
        }
        if(buffer->secondary_inited)
        {
            wake_all(&buffer->secondary_write_wq);
        }
    }

    dprintk(
        "pipe_fs_buffer_file_on_close: pipe(%ld) clients(%ld) servers(%ld)\n",
        (sl_t)pipe->pnode.key,
        (sl_t)buffer->num_clients,
        (sl_t)buffer->num_servers);

    pipe_lock_release(pipe);
    fs_node_put(node);

    return 0;
}

static struct fs_node_ops pipe_fs_buffer_node_ops = {
    .load_page = pipe_fs_buffer_node_load_page,
    .unload_page = pipe_fs_buffer_node_unload_page,

    .getattr = pipe_fs_buffer_node_getattr,

    .flush_page = fs_node_flush_page_nop,

    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(pipe_fs_buffer_node_ops);

static struct fs_file_ops pipe_fs_buffer_file_ops = {
    .read = pipe_fs_buffer_file_read,
    .write = pipe_fs_buffer_file_write,
    .poll = pipe_fs_buffer_file_poll,
    .status = pipe_fs_buffer_file_status,

    .on_open = pipe_fs_buffer_file_on_open,
    .on_close = pipe_fs_buffer_file_on_close,

    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
};
FS_FILE_OPS_INIT_UNDEF(pipe_fs_buffer_file_ops);

static int
pipe_fs_mount_create_pipe(struct pipe_fs_mount *mnt, size_t *inode_out);

static int
pipe_fs_mux_node_form_connection(struct pipe_fs_node *pipe,
                                      int can_block,
                                      int is_client,
                                      size_t *inode_out)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));
    DEBUG_ASSERT(pipe->type == PIPE_FS_NODE_MUX);

    int status_waiting_for_us = is_client ? PIPE_MUX_STATUS_WAITING_FOR_CLIENT
                                          : PIPE_MUX_STATUS_WAITING_FOR_SERVER;
    int status_waiting_for_other = is_client ? PIPE_MUX_STATUS_WAITING_FOR_SERVER
                                             : PIPE_MUX_STATUS_WAITING_FOR_CLIENT;

    struct pipe_fs_mount *pipe_mnt;
    pipe_mnt =
        container_of(pipe->fs_node->mount, struct pipe_fs_mount, fs_mount);
    DEBUG_ASSERT(KERNEL_ADDR(pipe_mnt));

    size_t inode = 0;

    pipe_lock_acquire(pipe);

    struct pipe_fs_mux *mux;
    mux = pipe_fs_node_as_mux(pipe);
    DEBUG_ASSERT(KERNEL_ADDR(mux));

    while(1)
    {
        if(mux->status == PIPE_MUX_STATUS_NONE)
        {
            if(!can_block)
            {
                res = -EWOULDBLOCK;
                break;
            }
            mux->status = status_waiting_for_other;
            while(mux->status == status_waiting_for_other)
            {
                int irq_flags;
                res = wait_on_irq_lock_release(&mux->unpaired_wq,
                                               &pipe->lock,
                                               &irq_flags);
                enable_restore_irqs(irq_flags);
                if(res)
                {
                    return res;
                }
                // We could be interrupted here...
                pipe_lock_acquire(pipe);
            }
            if(mux->status == PIPE_MUX_STATUS_PAIRED)
            {
                // We are done (grab the inode and result saved by
                // the other end of the connection)
                res = mux->unpaired_result;
                inode = mux->unpaired_inode;
                mux->status = PIPE_MUX_STATUS_NONE;
                wake_all(&mux->pending_wq);
                break;
            }
            else
            {
                if(!can_block)
                {
                    res = -EWOULDBLOCK;
                    break;
                }
                // Try again?
                continue;
            }
        }
        else if((mux->status == status_waiting_for_other) ||
                (mux->status == PIPE_MUX_STATUS_PAIRED))
        {
            if(!can_block)
            {
                res = -EWOULDBLOCK;
                break;
            }
            // Put ourselves on the pending waitqueue and try again.
            int irq_flags;
            res = wait_on_irq_lock_release(&mux->pending_wq,
                                           &pipe->lock,
                                           &irq_flags);
            enable_restore_irqs(irq_flags);
            if(res)
            {
                return res;
            }
            // We could be interrupted here...
            pipe_lock_acquire(pipe);
            continue;
        }
        else if(mux->status == status_waiting_for_us)
        {
            // We are the second to arrive.
            res = pipe_fs_mount_create_pipe(pipe_mnt, &inode);
            mux->unpaired_inode = inode;
            mux->unpaired_result = res;
            mbarrier();
            mux->status = PIPE_MUX_STATUS_PAIRED;
            wake_all(&mux->unpaired_wq);
            break;
        }
    }
    pipe_lock_release(pipe);

    *inode_out = inode;
    return res;
}

static int
pipe_fs_mux_node_accept(struct fs_node *fs_node,
                             size_t *inode_out,
                             unsigned long flags)
{
    struct pipe_fs_node *pipe = fs_node->backing.priv_state;
    int can_block = !(flags & FS_NODE_ACCEPT_NON_BLOCKING);
    return pipe_fs_mux_node_form_connection(pipe,
                                            can_block,
                                            0,
                                            inode_out);
}

static int
pipe_fs_mux_node_connect(struct fs_node *fs_node,
                              size_t *inode_out,
                              unsigned long flags)
{
    struct pipe_fs_node *pipe = fs_node->backing.priv_state;
    int can_block = !(flags & FS_NODE_CONNECT_NON_BLOCKING);
    return pipe_fs_mux_node_form_connection(pipe,
                                            can_block,
                                            1,
                                            inode_out);
}

static struct fs_node_ops pipe_fs_mux_node_ops = {
    .accept = pipe_fs_mux_node_accept,
    .connect = pipe_fs_mux_node_connect,
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(pipe_fs_mux_node_ops);

static struct fs_file_ops pipe_fs_mux_file_ops = {
    .flush = fs_file_nop_flush,
};
FS_FILE_OPS_INIT_UNDEF(pipe_fs_mux_file_ops);

static int
pipe_fs_mount_create_pipe(struct pipe_fs_mount *mnt, size_t *inode_out)
{
    int res;

    struct pipe_fs_buffer *buffer = kzmalloc(sizeof(*buffer), KM_KERNEL);
    if(buffer== NULL)
    {
        return -ENOMEM;
    }
    buffer->node.type = PIPE_FS_NODE_BUFFER;

    irq_lock_init(&buffer->node.lock);

    buffer->num_readers = 0;
    buffer->num_writers = 0;
    buffer->num_clients = 0;
    buffer->num_servers = 0;

    buffer->primary_inited = 0;
    buffer->secondary_inited = 0;

    irq_lock_init(&buffer->page_tree_lock);
    ptree_init(&buffer->page_tree);

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_insert_any(&mnt->inode_tree, &buffer->node.pnode);
    irq_lock_release(&mnt->inode_tree_lock);

    *inode_out = buffer->node.pnode.key;

    return 0;
}
static int
pipe_fs_mount_destroy_pipe(struct pipe_fs_mount *mnt,
                             struct pipe_fs_node *node)
{
    struct pipe_fs_buffer *buffer;
    buffer = pipe_fs_node_as_buffer(node);
    DEBUG_ASSERT(KERNEL_ADDR(buffer));

    if(buffer->primary_inited)
    {
        waitqueue_deinit(&buffer->primary_write_wq);
        waitqueue_deinit(&buffer->primary_read_wq);
    }
    if(buffer->secondary_inited)
    {
        waitqueue_deinit(&buffer->secondary_write_wq);
        waitqueue_deinit(&buffer->secondary_read_wq);
    }

    // Never release this lock...
    irq_lock_acquire(&buffer->page_tree_lock);
    struct ptree_node *pnode = ptree_get_first(&buffer->page_tree);
    while(pnode)
    {
        struct pipe_page *pg =
            container_of(pnode, struct pipe_page, ptree_node);
        ptree_remove(&buffer->page_tree, pg->ptree_node.key);
        page_free(VMEM_MIN_PAGE_ORDER, pg->addr);
        kfree(pg);
        pnode = ptree_get_first(&buffer->page_tree);
    }

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_remove(&mnt->inode_tree, node->pnode.key);
    irq_lock_release(&mnt->inode_tree_lock);

    if(buffer->primary_inited)
    {
        ringbuf_deinit(&buffer->primary_ringbuf);
    }
    if(buffer->secondary_inited)
    {
        ringbuf_deinit(&buffer->secondary_ringbuf);
    }

    kfree(node);

    return 0;
}

static int
pipe_fs_buffer_ensure_primary_inited(
        struct pipe_fs_buffer *buffer)
{
    int res;
    if(!buffer->primary_inited)
    {
        waitqueue_init(&buffer->primary_read_wq);
        waitqueue_name(&buffer->primary_read_wq, "pipe-read-primary");
        waitqueue_init(&buffer->primary_write_wq);
        waitqueue_name(&buffer->primary_write_wq, "pipe-write-primary");
        res = ringbuf_init(&buffer->primary_ringbuf, PIPE_RINGBUF_LEN);
        if(res)
        {
            waitqueue_deinit(&buffer->primary_read_wq);
            waitqueue_deinit(&buffer->primary_write_wq);
            return res;
        }
        buffer->primary_inited = 1;
    }
    return 0;
}

static int
pipe_fs_buffer_ensure_secondary_inited(
        struct pipe_fs_buffer *buffer)
{
    int res;
    if(!buffer->secondary_inited)
    {
        waitqueue_init(&buffer->secondary_read_wq);
        waitqueue_name(&buffer->secondary_read_wq, "pipe-read-secondary");
        waitqueue_init(&buffer->secondary_write_wq);
        waitqueue_name(&buffer->secondary_write_wq, "pipe-write-secondary");
        res = ringbuf_init(&buffer->secondary_ringbuf, PIPE_RINGBUF_LEN);
        if(res)
        {
            waitqueue_deinit(&buffer->secondary_read_wq);
            waitqueue_deinit(&buffer->secondary_write_wq);
            return res;
        }
        buffer->secondary_inited = 1;
    }
    return 0;
}

static int
pipe_fs_mount_create_mux(struct pipe_fs_mount *mnt, size_t *inode_out)
{
    struct pipe_fs_mux *mux = kzmalloc(sizeof(*mux), KM_KERNEL);
    if(mux == NULL)
    {
        return -ENOMEM;
    }
    mux->node.type = PIPE_FS_NODE_MUX;
    irq_lock_init(&mux->node.lock);

    waitqueue_init(&mux->pending_wq);
    waitqueue_name(&mux->pending_wq, "pipe-pending");
    waitqueue_init(&mux->unpaired_wq);
    waitqueue_name(&mux->unpaired_wq, "pipe-unpaired");

    mux->status = PIPE_MUX_STATUS_NONE;
    mux->unpaired_result = 0;
    mux->unpaired_inode = 0;

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_insert_any(&mnt->inode_tree, &mux->node.pnode);
    irq_lock_release(&mnt->inode_tree_lock);

    *inode_out = mux->node.pnode.key;

    return 0;
}
static int
pipe_fs_mount_destroy_mux(struct pipe_fs_mount *mnt,
                               struct pipe_fs_node *node)
{
    struct pipe_fs_mux *mux;
    mux = pipe_fs_node_as_mux(node);
    DEBUG_ASSERT(KERNEL_ADDR(mux));

    waitqueue_deinit(&mux->pending_wq);
    waitqueue_deinit(&mux->unpaired_wq);

    irq_lock_acquire(&mnt->inode_tree_lock);
    ptree_remove(&mnt->inode_tree, node->pnode.key);
    irq_lock_release(&mnt->inode_tree_lock);

    kfree(node);

    return 0;
}

static int
pipe_fs_root_index(struct fs_mount *mnt, size_t *index)
{
    return -EINVAL;
}

static int
pipe_fs_load_node(struct fs_mount *fs_mount,
                    size_t index,
                    struct fs_node *fs_node)
{
    struct pipe_fs_mount *mnt;
    mnt = container_of(fs_mount, struct pipe_fs_mount, fs_mount);
    irq_lock_acquire(&mnt->inode_tree_lock);
    struct ptree_node *pnode = ptree_get(&mnt->inode_tree, index);
    if(pnode == NULL)
    {
        irq_lock_release(&mnt->inode_tree_lock);
        return -ENXIO;
    }
    struct pipe_fs_node *node;
    node = container_of(pnode, struct pipe_fs_node, pnode);
    DEBUG_ASSERT(KERNEL_ADDR(fs_node));

    switch(node->type)
    {
    case PIPE_FS_NODE_MUX:
        fs_node->backing.node_ops = &pipe_fs_mux_node_ops;
        fs_node->backing.file_ops = &pipe_fs_mux_file_ops;
        break;
    case PIPE_FS_NODE_BUFFER:
        fs_node->backing.node_ops = &pipe_fs_buffer_node_ops;
        fs_node->backing.file_ops = &pipe_fs_buffer_file_ops;
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
pipe_fs_unload_node(struct fs_mount *fs_mount,
                      size_t index,
                      struct fs_node *fs_node)
{
    int res;

    struct pipe_fs_node *node = fs_node->backing.priv_state;
    DEBUG_ASSERT(node->fs_node == fs_node);
    DEBUG_ASSERT(node->pnode.key == index);

    struct pipe_fs_mount *mnt;
    mnt = container_of(fs_mount, struct pipe_fs_mount, fs_mount);

    switch(node->type)
    {
    case PIPE_FS_NODE_MUX:
        res = pipe_fs_mount_destroy_mux(mnt, node);
        if(res)
        {
            return res;
        }
        break;
    case PIPE_FS_NODE_BUFFER:
        res = pipe_fs_mount_destroy_pipe(mnt, node);
        if(res)
        {
            return res;
        }
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static struct fs_mount_ops pipe_fs_mount_ops = {
    .root_index = pipe_fs_root_index,
    .load_node = pipe_fs_load_node,
    .unload_node = pipe_fs_unload_node,
    .sync = fs_mount_nop_sync,
};

static int
pipe_fs_mount_init(struct pipe_fs_mount *mnt)
{
    int res;

    irq_lock_init(&mnt->inode_tree_lock);
    ptree_init(&mnt->inode_tree);

    res = init_fs_mount_struct(&mnt->fs_mount, &pipe_fs_mount_ops);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
init_pipe_fs(void)
{
    int res;
    res = pipe_fs_mount_init(&pipe_fs_mount);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(fs, init_pipe_fs);

struct fs_node *
pipe_create_pipe_anonymous(void)
{
    int res;
    size_t inode;
    res = pipe_fs_mount_create_pipe(&pipe_fs_mount, &inode);
    if(res)
    {
        return NULL;
    }
    struct fs_node *fs_node;
    fs_node = fs_mount_get_node(&pipe_fs_mount.fs_mount, inode);
    return fs_node;
}

struct fs_node *
pipe_create_mux_anonymous(void)
{
    int res;
    size_t inode;
    res = pipe_fs_mount_create_mux(&pipe_fs_mount, &inode);
    if(res)
    {
        return NULL;
    }
    struct fs_node *fs_node;
    fs_node = fs_mount_get_node(&pipe_fs_mount.fs_mount, inode);
    return fs_node;
}
