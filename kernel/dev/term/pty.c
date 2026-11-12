
#include <kanawha/dev/term.h>
#include <kanawha/ringbuf.h>
#include <kanawha/uapi/file.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>

#define PTY_READ_BUFLEN (128)
#define PTY_NAMEBUFLEN (32)

struct ptmx_node {
    struct vfs_node vfs_node;
};

struct pty_node
{
    struct vfs_node vfs_node;

    struct term_dev term_dev;
    
    thread_lock_t read_lock;
    struct ringbuf read_buffer;
    struct waitqueue read_wq;

    char namebuf[PTY_NAMEBUFLEN];
};

struct pty_mount {
    struct vfs_mount *vfs_mount;
    struct ptmx_node ptmx_node;
};

static struct pty_mount pty_mnt = {0};

// pty node

static ssize_t
pty_ctrl_file_read(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL) {
        return -EINVAL;
    }

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct pty_node *pty_node = container_of(vfs_node, struct pty_node, vfs_node);

    ssize_t total_read = 0;

    thread_lock_acquire(&pty_node->read_lock);
    while(total_read == 0) {
        ssize_t amt_read = ringbuf_read(
                &pty_node->read_buffer,
                buf,
                buflen);
        if(amt_read == 0) {
            if(flags & FS_FILE_READ_NON_BLOCKING) {
                thread_lock_release(&pty_node->read_lock);
                fs_node_put(fs_node);
                return -EWOULDBLOCK;
            }
            res = wait_on_thread_lock_release(
                    &pty_node->read_wq,
                    &pty_node->read_lock);
            if(res) {
                fs_node_put(fs_node);
                return res;
            }
            thread_lock_acquire(&pty_node->read_lock);
        }
        else if(amt_read < 0)
        {
            thread_lock_release(&pty_node->read_lock);
            fs_node_put(fs_node);
            return amt_read;
        }
        total_read = amt_read;
    }
    thread_lock_release(&pty_node->read_lock);

    term_driver_poke_output(&pty_node->term_dev);

    fs_node_put(fs_node);

    return total_read;
}

static ssize_t
pty_ctrl_file_write(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL) {
        return -ENXIO;
    }

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
    if(total > 0) {
        wake_single(&pty_node->read_wq);
    }

    fs_node_put(fs_node);
    return total;
}

static struct fs_node_ops
pty_ctrl_node_ops = {
    .flush = fs_node_flush_nop,

    VFS_NODE_OPS_INITIALIZERS
};
FS_NODE_OPS_INIT_UNDEF(pty_ctrl_node_ops);

static struct fs_file_ops
pty_ctrl_file_ops = {
    .read = pty_ctrl_file_read,
    .write = pty_ctrl_file_write,
    .flush = fs_file_nop_flush,

    VFS_FILE_OPS_INITIALIZERS
};
FS_FILE_OPS_INIT_UNDEF(pty_ctrl_file_ops);

static int
pty_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    int res;
    struct pty_node *pty = container_of(term_dev, struct pty_node, term_dev);
    thread_lock_acquire(&pty->read_lock);
    res = ringbuf_write(&pty->read_buffer, &c, 1);
    thread_lock_release(&pty->read_lock);
    wake_single(&pty->read_wq);
    return res;
}

static int 
pty_term_dev_flush(struct term_dev *term_dev)
{
    struct pty_node *pty = container_of(term_dev, struct pty_node, term_dev);
    return 0;
}

static struct term_driver
pty_term_driver = {
    .get_baudrate = term_dev_get_baudrate_zero,
    .set_baudrate = term_dev_set_baudrate_zero,
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

    node->vfs_node.fs_node_ops = &pty_ctrl_node_ops;
    node->vfs_node.fs_file_ops = &pty_ctrl_file_ops;

    thread_lock_init(&node->read_lock);

    res = ringbuf_init(&node->read_buffer, PTY_READ_BUFLEN);
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
        ringbuf_deinit(&node->read_buffer);
        kfree(node);
        return res;
    }

    snprintk(node->namebuf, PTY_NAMEBUFLEN,
             "pty%lu", (ul_t)inode);
    node->namebuf[PTY_NAMEBUFLEN-1] = '\0';
    waitqueue_init(&node->read_wq);
    waitqueue_name(&node->read_wq, node->namebuf);

    node->term_dev.driver = &pty_term_driver;

    res = register_term_dev(&node->term_dev, node->namebuf);
    if(res) {
        vfs_mount_remove_node(mnt->vfs_mount, &node->vfs_node);
        ringbuf_deinit(&node->read_buffer);
        kfree(node);
        return res;
    }

    res = vfs_mount_link_root(
            mnt->vfs_mount,
            node->namebuf,
            inode);
    if(res) {
        vfs_mount_remove_node(mnt->vfs_mount, &node->vfs_node);
        ringbuf_deinit(&node->read_buffer);
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
    VFS_NODE_OPS_INITIALIZERS
};
FS_NODE_OPS_INIT_UNDEF(ptmx_node_ops);

static struct fs_file_ops
ptmx_file_ops = {
    VFS_FILE_OPS_INITIALIZERS
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
