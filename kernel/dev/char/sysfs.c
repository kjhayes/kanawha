
#include <kanawha/dev/char.h>

#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/lock.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>
#include <kanawha/string.h>

struct char_dev_fs_node {
    struct char_dev *dev;
    struct vfs_node vfs_node;
};

static inline struct char_dev *
__fs_node_to_char_dev(
        struct fs_node *node)
{
    struct char_dev_fs_node *__c =
        container_of(node, struct char_dev_fs_node, vfs_node.fs_node);
    return __c->dev;
}

static struct vfs_mount *char_dev_fs_mount = NULL;
static struct fs_node_ops char_dev_fs_node_ops;
static struct fs_file_ops char_dev_fs_file_ops;
static struct char_dev_registry_hook *char_dev_fs_hook = NULL;

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

    struct char_dev *dev = __fs_node_to_char_dev(fs_node);

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

    struct char_dev *dev = __fs_node_to_char_dev(fs_node);

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

    struct char_dev *dev = __fs_node_to_char_dev(fs_node);

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
    struct char_dev *dev = __fs_node_to_char_dev(fs_node);

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

static void
char_dev_sysfs_on_register(
        struct char_dev *dev)
{
    int res;
    struct char_dev_fs_node *node = kmalloc(sizeof(*node));
    if(node == NULL) {
        wprintk("Failed to register character device with sysfs!\n");
        return;
    }
    node->dev = dev;

    node->vfs_node.fs_node.node_ops = &char_dev_fs_node_ops;
    node->vfs_node.fs_node.file_ops = &char_dev_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(
            char_dev_fs_mount,
            &node->vfs_node,
            char_dev_get_name(dev));
    if(res) {
        kfree(node);
        wprintk("Failed to register character device with sysfs!\n");
        return;
    }
}

static void
char_dev_sysfs_on_unregister(
        struct char_dev *dev)
{
    panic("Tried to deregister char_dev from sysfs! (UNIMPL)\n");
    return;
}

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

    char_dev_fs_mount = mnt;

    struct char_dev_registry_hook *hook = hook_char_dev_registry(
            char_dev_sysfs_on_register,
            char_dev_sysfs_on_unregister);
    if(hook == NULL) {
        char_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    char_dev_fs_hook = hook;

    res = sysfs_register_mount(&char_dev_fs_mount->fs_mount, "chardev");
    if(res) {
        char_dev_fs_hook = NULL;
        unhook_char_dev_registry(hook);
        char_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, char_dev_init_fs_mount, "Registering chardev Sysfs Mount");

