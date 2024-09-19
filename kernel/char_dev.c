
#include <kanawha/char_dev.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/file.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>
#include <kanawha/string.h>

static DECLARE_SPINLOCK(char_dev_tree_lock);
static size_t num_char_dev = 0;
static DECLARE_STREE(char_dev_tree);
static DECLARE_PTREE(char_dev_fs_node_tree);

static struct flat_mount *char_dev_fs_mount = NULL;
static struct fs_node_ops char_dev_fs_node_ops;
static struct fs_file_ops char_dev_fs_file_ops;

int
register_char_dev(
        struct char_dev *chr,
        const char *name,
        struct char_driver *driver,
        struct device *device)
{
    int res;

    spin_lock(&char_dev_tree_lock);

    struct stree_node *existing = stree_get(&char_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&char_dev_tree_lock);
        return -EEXIST;
    }

    chr->device = device;
    chr->driver = driver;
    dprintk("Registering char_dev \"%s\" name=%p\n", name, name);
    chr->char_dev_node.key = name;

    chr->flat_fs_node.fs_node.file_ops = &char_dev_fs_file_ops;
    chr->flat_fs_node.fs_node.node_ops = &char_dev_fs_node_ops;

    stree_insert(&char_dev_tree, &chr->char_dev_node);

    // Assign the node a fs_node index
    if(char_dev_fs_mount != NULL) {
        res = flat_mount_insert_node(
                char_dev_fs_mount,
                &chr->flat_fs_node,
                name);
        if(res) {
            stree_remove(&char_dev_tree, name);
            spin_unlock(&char_dev_tree_lock);
            return res;
        }
    }

    num_char_dev++;

    spin_unlock(&char_dev_tree_lock);
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
    spin_lock(&char_dev_tree_lock);
    struct stree_node *node = stree_get(&char_dev_tree, name);
    spin_unlock(&char_dev_tree_lock);
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
        ssize_t amount)
{
    struct fs_node *fs_node =
        file->path->fs_node;
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, flat_fs_node.fs_node);

    amount = char_dev_read(dev, buffer, amount);

    return amount;
}

static ssize_t
char_dev_fs_node_write(
        struct file *file,
        void *buffer,
        ssize_t amount)
{
    struct fs_node *fs_node =
        file->path->fs_node;
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, flat_fs_node.fs_node);

    amount = char_dev_write(dev, buffer, amount);

    return amount;
}

static int
char_dev_fs_node_flush(
        struct file *file,
        unsigned long flags)
{
    struct fs_node *fs_node =
        file->path->fs_node;
    struct char_dev *dev =
        container_of(fs_node, struct char_dev, flat_fs_node.fs_node);

    return char_dev_flush(dev);
}

static struct fs_node_ops
char_dev_fs_node_ops = {
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static struct fs_file_ops
char_dev_fs_file_ops = {
    .read = char_dev_fs_node_read,
    .write = char_dev_fs_node_write,
    .flush = char_dev_fs_node_flush,
    .seek = fs_file_seek_pinned_zero,
};

static int
char_dev_init_fs_mount(void)
{
    int res;

    struct flat_mount *mnt;
    mnt = flat_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create flat mount!\n");
        return -ENOMEM;
    }

    spin_lock(&char_dev_tree_lock);

    char_dev_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&char_dev_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct char_dev *dev =
            container_of(node, struct char_dev, char_dev_node);
        res = flat_mount_insert_node(
                mnt,
                &dev->flat_fs_node,
                node->key);
        if(res) {
            spin_lock(&char_dev_tree_lock);
            return res;
        }
    }
    spin_unlock(&char_dev_tree_lock);

    res = sysfs_register_mount(&char_dev_fs_mount->fs_mount, "chardev");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, char_dev_init_fs_mount, "Registering chardev Sysfs Mount");

