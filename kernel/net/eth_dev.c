
#include <kanawha/net/eth_dev.h>
#include <kanawha/stree.h>
#include <kanawha/lock.h>
#include <kanawha/stddef.h>
#include <kanawha/fs/sys/sysfs.h>

static DECLARE_STREE(eth_dev_tree);
DEFINE_LOCAL_THREAD_LOCK(eth_dev_tree_lock);

static struct vfs_mount *eth_dev_fs_mount = NULL;
static struct fs_node_ops eth_dev_fs_node_ops;
static struct fs_file_ops eth_dev_fs_file_ops;

int
register_eth_dev(
        struct eth_dev *dev,
        const char *name,
        struct eth_driver *driver)
{
    int res;

    eth_dev_tree_lock_acquire();

    dev->driver = driver;
    dev->eth_dev_node.key = name;

    struct stree_node *existing = stree_get(&eth_dev_tree, name);
    if(existing != NULL) {
        eth_dev_tree_lock_release();
        return -ENXIO;
    }

    dev->vfs_node.fs_node.unload = NULL;
    dev->vfs_node.fs_node.file_ops = &eth_dev_fs_file_ops;
    dev->vfs_node.fs_node.node_ops = &eth_dev_fs_node_ops;

    res = stree_insert(&eth_dev_tree, &dev->eth_dev_node);
    if(res) {
        eth_dev_tree_lock_release();
        return res;
    }

    // Assign the node a fs_node index
    if(eth_dev_fs_mount != NULL) {
        res = vfs_mount_insert_node_and_link_root(
                eth_dev_fs_mount,
                &dev->vfs_node,
                name);
        if(res) {
            stree_remove(&eth_dev_tree, name);
            eth_dev_tree_lock_release();
            return res;
        }
    }

    eth_dev_tree_lock_release();

    struct eth_mac_addr addr;
    res = eth_dev_read_mac(dev, &addr);
    if(res) {
        printk("Failed to get registered network device MAC address!\n");
        return res;
    }
    printk("Registered Ethernet Device \"%s\" MAC=[",
            name);
    dump_eth_mac_addr(do_printk, &addr);
    do_printk("]\n");
    return 0;
}

struct eth_dev *
eth_dev_find(const char *name)
{
    eth_dev_tree_lock_acquire();
    struct stree_node *node = stree_get(&eth_dev_tree, name);
    eth_dev_tree_lock_release();
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct eth_dev, eth_dev_node);
}

static ssize_t 
eth_dev_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct eth_dev *dev = container_of(fs_node, struct eth_dev, vfs_node.fs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    size_t amt_read = 0;

    // TODO

    return amt_read;
}

static ssize_t 
eth_dev_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct eth_dev *dev = container_of(fs_node, struct eth_dev, vfs_node.fs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    if(amount < sizeof(struct eth_frame_header)) {
        return -EINVAL;
    }

    res = eth_dev_send_frame(dev, (struct eth_frame*)buffer, amount, 0);
    if(res) {
        return res;
    }

    return amount;
}

static struct fs_node_ops
eth_dev_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
    .flush = fs_node_flush_nop,
    .setattr = fs_node_cannot_setattr,
    .getattr = fs_node_cannot_getattr,
};

static struct fs_file_ops
eth_dev_fs_file_ops =
{
    .read = eth_dev_fs_file_read,
    .write = eth_dev_fs_file_write,
    .flush = fs_file_cannot_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,
    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
eth_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create eth_dev VFS mount!\n");
        return -ENOMEM;
    }

    eth_dev_tree_lock_acquire();

    eth_dev_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&eth_dev_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct eth_dev *dev =
            container_of(node, struct eth_dev, eth_dev_node);
        res = vfs_mount_insert_node_and_link_root(
                mnt,
                &dev->vfs_node,
                node->key);
        if(res) {
            eth_dev_tree_lock_release();
            return res;
        }
    }
    eth_dev_tree_lock_release();

    res = sysfs_register_mount(&eth_dev_fs_mount->fs_mount, "ethdev");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, eth_dev_init_fs_mount, "Registering chardev Sysfs Mount");

