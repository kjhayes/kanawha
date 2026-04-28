
#include <kanawha/dev/term.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>

#define PTY_NAMEBUFLEN (32)

struct ptmx_node {
    struct vfs_node vfs_node;
};

struct pty_node
{
    struct vfs_node vfs_node;

    struct term_dev term_dev;

    char namebuf[PTY_NAMEBUFLEN];
};

struct pty_mount {
    struct vfs_mount *vfs_mount;
    struct ptmx_node ptmx_node;
};

static struct pty_mount pty_mnt = {0};

// pty node

static struct fs_node_ops
pty_node_ops = {
};
FS_NODE_OPS_INIT_UNDEF(pty_node_ops);

static struct fs_file_ops
pty_file_ops = {
};
FS_FILE_OPS_INIT_UNDEF(pty_file_ops);

static int
pty_term_dev_putc(
        struct term_dev *term_dev,
        char c)
{
    return -EUNIMPL;
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

    size_t inode;

    res = vfs_mount_insert_node(
            mnt->vfs_mount,
            &node->vfs_node,
            &inode);
    if(res) {
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
        kfree(node);
        return res;
    }

    res = vfs_mount_link_root(
            mnt->vfs_mount,
            node->namebuf,
            inode);
    if(res) {
        vfs_mount_remove_node(mnt->vfs_mount, &node->vfs_node);
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
