
#include <kanawha/dev/term.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>

#define PTY_READ_BUFLEN (128)
#define PTY_NAMEBUFLEN (32)

struct pty_ringbuf
{
    thread_lock_t lock;
    size_t head;
    size_t tail;
    size_t buflen;
    void *buffer;
};

struct ptmx_node {
    struct vfs_node vfs_node;
};

struct pty_node
{
    struct vfs_node vfs_node;

    struct term_dev term_dev;

    struct pty_ringbuf read_buffer;

    char namebuf[PTY_NAMEBUFLEN];
};

struct pty_mount {
    struct vfs_mount *vfs_mount;
    struct ptmx_node ptmx_node;
};

static struct pty_mount pty_mnt = {0};

// pty ringbuf

static int
pty_ringbuf_init(
        struct pty_ringbuf *buf,
        size_t len)
{
    thread_lock_init(&buf->lock);
    buf->head = 0;
    buf->tail = 0;
    buf->buflen = len;
    buf->buffer = kmalloc(len, KM_KERNEL);
    if(buf->buffer == NULL) {
        buf->buflen = 0;
        return -ENOMEM;
    }
    return 0;
}

static int
pty_ringbuf_deinit(
        struct pty_ringbuf *buf)
{
    kfree(buf->buffer);

    // Pedantic...
    buf->head = 0;
    buf->tail = 0;
    buf->buflen = 0;
    buf->buffer = NULL;

    return 0;
}

static inline void
pty_ringbuf_lock(struct pty_ringbuf *buf)
{
    thread_lock_acquire(&buf->lock);
}

static inline void
pty_ringbuf_unlock(struct pty_ringbuf *buf)
{
    thread_lock_release(&buf->lock);
}

static int
pty_ringbuf_empty(
        struct pty_ringbuf *buf)
{
    if(buf->head == buf->tail) {
        // Greedily "reset" the head and tail
        // to zero whenever we see that the buffer
        // is empty.
        buf->head = 0;
        buf->tail = 0;
        return 1;
    } else {
        return 0;
    }
}
static int
pty_ringbuf_full(
        struct pty_ringbuf *buf)
{
    if(buf->buflen <= 0) {
        return 1;
    }
    return ((buf->head+1)%buf->buflen) == buf->tail;
}

static ssize_t
pty_ringbuf_read(
        struct pty_ringbuf *buf,
        void *into,
        size_t len)
{
    ssize_t total = 0;
    while(len > 0 && !pty_ringbuf_empty(buf)) {
        size_t space = 0;
        if(buf->tail < buf->head) {
            space = buf->head - buf->tail;
        } else {
            space = buf->buflen - buf->tail;
        }

        if(space > len) {
            space = len;
        }
        memcpy(into, &buf->buffer[buf->tail], space);
        into += space;
        len -= space;
        total += space;
        buf->tail += space;
        if(buf->tail >= buf->buflen) {
            buf->tail = 0;
        } 
    }
    return total;
}

static int
pty_ringbuf_putc(
        struct pty_ringbuf *ringbuf,
        char c)
{
    if(pty_ringbuf_full(ringbuf)) {
        return -EWOULDBLOCK;
    }
    ((char*)ringbuf->buffer)[ringbuf->head] = c;
    ringbuf->head++;
    if(ringbuf->head >= ringbuf->buflen) {
        ringbuf->head = 0;
    }
    return 0;
}

// pty node

static ssize_t
pty_file_read(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct pty_node *pty_node = container_of(vfs_node, struct pty_node, vfs_node);

    pty_ringbuf_lock(&pty_node->read_buffer);
    ssize_t amt_read = pty_ringbuf_read(
            &pty_node->read_buffer,
            buf,
            buflen);
    pty_ringbuf_unlock(&pty_node->read_buffer);

    if(amt_read == 0) {
        // TODO: We should be blocking here if we can...
        return -EWOULDBLOCK;
    } else if(amt_read < 0) {
        return amt_read;
    }

    term_driver_poke_output(&pty_node->term_dev);
    return amt_read;
}

static ssize_t
pty_file_write(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct pty_node *pty_node = container_of(vfs_node, struct pty_node, vfs_node);

    ssize_t total = 0;
    while(buflen > 0) {
        res = term_driver_provide_input(
                &pty_node->term_dev,
                *(char*)buf);
        if(res) {
            break;
        }
        total++;
        buf++;
        buflen--;
    }
    return total;
}

static struct fs_node_ops
pty_node_ops = {
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(pty_node_ops);

static struct fs_file_ops
pty_file_ops = {
    .read = pty_file_read,
    .write = pty_file_write,
    .flush = fs_file_nop_flush,
};
FS_FILE_OPS_INIT_UNDEF(pty_file_ops);

static int
pty_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    int res;
    struct pty_node *pty = container_of(term_dev, struct pty_node, term_dev);
    pty_ringbuf_lock(&pty->read_buffer);
    res = pty_ringbuf_putc(&pty->read_buffer, c);
    if(res) {
        pty_ringbuf_unlock(&pty->read_buffer);
        return res;
    }
    pty_ringbuf_unlock(&pty->read_buffer);
    return 0;
}

static int 
pty_term_dev_flush(struct term_dev *term_dev)
{
    return 0;
}

static struct term_driver
pty_term_driver = {
    .get_baudrate = term_dev_cannot_get_baudrate,
    .set_baudrate = term_dev_cannot_set_baudrate,
    .flush = pty_term_dev_flush,
    .putc = pty_term_dev_putc,
};

static int
pty_mount_create_pty(struct pty_mount *mnt, size_t *inode_out)
{
    int res;

    struct pty_node *node = kzmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return -ENOMEM;
    }

    node->vfs_node.fs_node_ops = &pty_node_ops;
    node->vfs_node.fs_file_ops = &pty_file_ops;

    res = pty_ringbuf_init(&node->read_buffer, PTY_READ_BUFLEN);
    if(res) {
        kfree(node);
        return res;
    }

    size_t inode;

    res = vfs_mount_insert_node(
            mnt->vfs_mount,
            &node->vfs_node,
            &inode);
    if(res) {
        pty_ringbuf_deinit(&node->read_buffer);
        kfree(node);
        return res;
    }

    snprintk(node->namebuf, PTY_NAMEBUFLEN,
             "pty%lu", (ul_t)inode);
    node->namebuf[PTY_NAMEBUFLEN-1] = '\0';

    node->term_dev.driver = &pty_term_driver;

    res = register_term_dev(&node->term_dev, node->namebuf);
    if(res) {
        vfs_mount_remove_node(mnt->vfs_mount, &node->vfs_node);
        pty_ringbuf_deinit(&node->read_buffer);
        kfree(node);
        return res;
    }

    res = vfs_mount_link_root(
            mnt->vfs_mount,
            node->namebuf,
            inode);
    if(res) {
        vfs_mount_remove_node(mnt->vfs_mount, &node->vfs_node);
        pty_ringbuf_deinit(&node->read_buffer);
        kfree(node);
        return res;
    }

    if(inode_out) {
        *inode_out = inode;
    }
    
    return 0;
}

// ptmx node

static int
ptmx_node_connect(
        struct fs_node *fs_node,
        size_t *conn_inode,
        unsigned long flags)
{
    int res;
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct ptmx_node *ptmx = container_of(vfs_node, struct ptmx_node, vfs_node);
    struct pty_mount *mnt = container_of(ptmx, struct pty_mount, ptmx_node);
    return pty_mount_create_pty(mnt, conn_inode);
}

static struct fs_node_ops
ptmx_node_ops = {
    .connect = ptmx_node_connect,
};
FS_NODE_OPS_INIT_UNDEF(ptmx_node_ops);

static struct fs_file_ops
ptmx_file_ops = {
};
FS_FILE_OPS_INIT_UNDEF(ptmx_file_ops);

static int
pty_init_ptmx(struct pty_mount *mnt)
{
    int res;

    mnt->ptmx_node.vfs_node.fs_node_ops = &ptmx_node_ops;
    mnt->ptmx_node.vfs_node.fs_file_ops = &ptmx_file_ops;
    
    res = vfs_mount_insert_node_and_link_root(
            mnt->vfs_mount,
            &mnt->ptmx_node.vfs_node,
            "ptmx");
    if(res) {
        return res;
    }
    return 0;
}

static int
pty_deinit_ptmx(struct pty_mount *mnt)
{
    int res;
    res = vfs_mount_remove_node(mnt->vfs_mount, &mnt->ptmx_node.vfs_node);
    if(res) {
        return res;
    }
    return 0;
}

static int
pty_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        eprintk("Failed to create pty VFS mount!\n");
        return -ENOMEM;
    }
    pty_mnt.vfs_mount = mnt;

    res = pty_init_ptmx(&pty_mnt);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&mnt->fs_mount, "pty");
    if(res)
    {
        pty_deinit_ptmx(&pty_mnt);
        pty_mnt.vfs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs,
                  pty_init_fs_mount,
                  "Registering pty Sysfs Mount");
