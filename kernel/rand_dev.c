
#include <kanawha/rand_dev.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/init.h>

static DECLARE_SPINLOCK(rand_dev_tree_lock);
static size_t num_rand_dev = 0;
static DECLARE_STREE(rand_dev_tree);
static struct vfs_mount *rand_dev_fs_mount = NULL;

static ssize_t 
rand_dev_fs_file_read(
        struct file *file,
        void * buf,
        ssize_t buflen,
        unsigned long flags
        )
{
    int res;

    struct rand_dev *dev =
        container_of(file->path->fs_node, struct rand_dev, vfs_node.fs_node);

    if(buflen <= 0) {
        return -EINVAL;
    }

    res = rand_dev_read(
            dev,
            buf,
            buflen);

    return res;
}

static struct fs_node_ops rand_dev_fs_node_ops = {
    .lookup = vfs_dir_lookup,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_cannot_flush,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr, 
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page, 
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
};

static struct fs_file_ops rand_dev_fs_file_ops =
{
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,

    .read = rand_dev_fs_file_read,
    .write = fs_file_cannot_read,
    .flush = fs_file_cannot_flush,
    .seek = fs_file_seek_pinned_zero,
};


static int
rand_dev_insert_vfs_nodes(
        struct rand_dev *dev)
{
    int res;

    dev->vfs_node.fs_node.node_ops = &rand_dev_fs_node_ops;
    dev->vfs_node.fs_node.file_ops = &rand_dev_fs_file_ops;

    size_t inode;

    res = vfs_mount_insert_node(
            rand_dev_fs_mount,
            &dev->vfs_node,
            &inode);
    if(res) {
        return res;
    }

    res = vfs_mount_link_root(
            rand_dev_fs_mount,
            dev->rand_dev_node.key,
            inode);
    if(res) {
        vfs_mount_remove_node(
                rand_dev_fs_mount,
                &dev->vfs_node);
        return res;
    }

    return 0;
}

int
register_rand_dev(
        struct rand_dev *dev,
        const char *name,
        struct rand_driver *driver)
{
    int res;
    dprintk("Registering FB Dev %s\n",
            name);
    spin_lock(&rand_dev_tree_lock);

    struct stree_node *existing = stree_get(&rand_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&rand_dev_tree_lock);
        return -EEXIST;
    }

    dev->driver = driver;
    dev->rand_dev_node.key = name;

    stree_insert(&rand_dev_tree, &dev->rand_dev_node);

    if(rand_dev_fs_mount != NULL)
    {
        res = rand_dev_insert_vfs_nodes(dev);
        if(res) {
            stree_remove(&rand_dev_tree, dev->rand_dev_node.key);
            spin_unlock(&rand_dev_tree_lock);
            return res;
        }
    }

    num_rand_dev++;

    spin_unlock(&rand_dev_tree_lock);
    return 0;
}

int
unregister_rand_dev(
        struct rand_dev *dev)
{
    return -EUNIMPL;
}

static int
rand_dev_init_fs_mount(void)
{
    int res;
    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create VFS mount for sysfs framebuffers!\n");
        return -ENOMEM;
    }

    spin_lock(&rand_dev_tree_lock);

    rand_dev_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&rand_dev_tree);
    for(; node != NULL; node = stree_get_next(node))
    {
        struct rand_dev *dev =
            container_of(node, struct rand_dev, rand_dev_node);
        res = rand_dev_insert_vfs_nodes(dev);
        if(res) {
            spin_unlock(&rand_dev_tree_lock);
            return res;
        }
    }
    spin_unlock(&rand_dev_tree_lock);

    res = sysfs_register_mount(
            &rand_dev_fs_mount->fs_mount,
            "randdev");
    if(res) {
        return res;
    }

    return 0;
}

declare_init_desc(fs, rand_dev_init_fs_mount, "Registering randdev Sysfs Mount");
