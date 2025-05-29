
#include <kanawha/char_dev.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/lock.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>
#include <kanawha/string.h>

static size_t num_char_dev = 0;
static DECLARE_STREE(char_dev_tree);
DEFINE_LOCAL_THREAD_LOCK(char_dev_tree_lock);

static struct vfs_mount *char_dev_fs_mount = NULL;
static struct fs_node_ops char_dev_fs_node_ops;
static struct fs_file_ops char_dev_fs_file_ops;

int
register_char_dev(
        struct char_dev *chr,
        const char *name,
        struct char_driver *driver)
{
    int res;

    char_dev_tree_lock_acquire();

    struct stree_node *existing = stree_get(&char_dev_tree, name);
    if(existing != NULL) {
        char_dev_tree_lock_release();
        return -EEXIST;
    }

    chr->driver = driver;
    dprintk("Registering char_dev \"%s\" name=%p\n", name, name);
    chr->char_dev_node.key = name;

    chr->vfs_node.fs_node.unload = NULL;
    chr->vfs_node.fs_node.file_ops = &char_dev_fs_file_ops;
    chr->vfs_node.fs_node.node_ops = &char_dev_fs_node_ops;

    stree_insert(&char_dev_tree, &chr->char_dev_node);

    // Assign the node a fs_node index
    if(char_dev_fs_mount != NULL) {
        res = vfs_mount_insert_node_and_link_root(
                char_dev_fs_mount,
                &chr->vfs_node,
                name);
        if(res) {
            stree_remove(&char_dev_tree, name);
            char_dev_tree_lock_release();
            return res;
        }
    }

    num_char_dev++;

    char_dev_tree_lock_release();
    return 0;
}

int
unregister_char_dev(struct char_dev *dev)
{
    return -EUNIMPL;
}

struct char_dev *
find_char_dev(const char *name)
{
    char_dev_tree_lock_acquire();
    struct stree_node *node = stree_get(&char_dev_tree, name);
    char_dev_tree_lock_release();
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct char_dev, char_dev_node);
}

// Chardev Sysfs

static ssize_t 
char_dev_fs_node_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct char_dev *dev =
        container_of(fs_node, struct char_dev, vfs_node.fs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return 0;
    }

    amount = char_dev_read(dev, buffer, amount);

    return amount;
}

static ssize_t
char_dev_fs_node_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, vfs_node.fs_node);

    if(flags & FS_FILE_WRITE_NON_BLOCKING) {
        return 0;
    }

    amount = char_dev_write(dev, buffer, amount);

    return amount;
}

static int
char_dev_fs_node_flush(
        struct file *file,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, vfs_node.fs_node);

    return char_dev_flush(dev);
}

static int
char_dev_fs_node_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            // We'll accept any value here and ignore it
            return 0;
    }
    return -EINVAL;
}

static int
char_dev_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, vfs_node.fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = 0;
            return 0;
    }
    return -EINVAL;
}
static struct fs_node_ops
char_dev_fs_node_ops =
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
    .setattr = char_dev_fs_node_setattr,
    .getattr = char_dev_fs_node_getattr,
};

static struct fs_file_ops
char_dev_fs_file_ops = {
    .read = char_dev_fs_node_read,
    .write = char_dev_fs_node_write,
    .flush = char_dev_fs_node_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,
    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
char_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create char_dev VFS mount!\n");
        return -ENOMEM;
    }

    char_dev_tree_lock_acquire();

    char_dev_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&char_dev_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct char_dev *dev =
            container_of(node, struct char_dev, char_dev_node);
        res = vfs_mount_insert_node_and_link_root(
                mnt,
                &dev->vfs_node,
                node->key);
        if(res) {
            char_dev_tree_lock_release();
            return res;
        }
    }
    char_dev_tree_lock_release();

    res = sysfs_register_mount(&char_dev_fs_mount->fs_mount, "chardev");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, char_dev_init_fs_mount, "Registering chardev Sysfs Mount");

static int
char_dev_dump_list(void) {
    int res;
    char_dev_tree_lock_acquire();
    struct stree_node *snode;
    printk("chardev {\n");
    for(snode = stree_get_first(&char_dev_tree);
        snode != NULL;
        snode = stree_get_next(snode)) {
        printk("\t%s\n", snode->key);
    }
    printk("}\n");
    char_dev_tree_lock_release();
    return 0;
}
declare_init(late, char_dev_dump_list);

