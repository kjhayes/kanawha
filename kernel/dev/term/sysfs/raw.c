
#include <kanawha/dev/term.h>
#include <kanawha/dev/term/sysfs.h>

#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/type.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/parse.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/types.h>

static ssize_t
term_dev_raw_fs_file_read(struct file *file,
                          void *buffer,
                          ssize_t amount,
                          unsigned long flags)
{
    int res;
    struct term_dev *dev = term_dev_from_file(file, raw_vfs_node);

    if(file->seek_offset != 0)
    {
        return 0;
    }

    snprintk(buffer, amount, "%d", (int)dev->mode.raw);

    return strnlen(buffer, amount);
}

static ssize_t
term_dev_raw_fs_file_write(struct file *file,
                           void *buffer,
                           ssize_t amount,
                           unsigned long flags)
{
#define BUFLEN 32

    int res;

    struct term_dev *dev = term_dev_from_file(file, raw_vfs_node);

    if(file->seek_offset != 0)
    {
        return 0;
    }

    if(flags & FS_FILE_WRITE_NON_BLOCKING)
    {
        return 0;
    }

    char tmp_buffer[BUFLEN];

    if(amount < BUFLEN)
    {
        tmp_buffer[amount] = '\0';
    }
    else
    {
        return -EINVAL;
    }

    memcpy(tmp_buffer, buffer, amount);

    printk("term_dev sysfs raw written with: \"%s\"\n", tmp_buffer);

    unsigned long value = parse_unsigned_long(tmp_buffer, 0);

    res = term_driver_set_raw(dev, value);
    if(res)
    {
        return res;
    }

    return amount;

#undef BUFLEN
}

static int
term_dev_raw_fs_file_flush(struct file *file, unsigned long flags)
{
    struct term_dev *dev = term_dev_from_file(file, raw_vfs_node);
    return 0;
}

static int
term_dev_raw_fs_node_setattr(struct fs_node *fs_node, int attr, size_t value)
{
    struct term_dev *dev = term_dev_from_node(fs_node, raw_vfs_node);

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        // We'll accept any value here and ignore it
        return 0;
    }
    return -EINVAL;
}

static int
term_dev_raw_fs_node_getattr(struct fs_node *fs_node, int attr, size_t *value)
{
    struct term_dev *dev = term_dev_from_node(fs_node, raw_vfs_node);

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        *value = 0;
        return 0;
    }

    return -EINVAL;
}

static struct fs_node_ops term_dev_raw_fs_node_ops = {
    .flush = fs_node_flush_nop,
    .setattr = term_dev_raw_fs_node_setattr,
    .getattr = term_dev_raw_fs_node_getattr,
    // ...
};
FS_NODE_OPS_INIT_UNDEF(term_dev_raw_fs_node_ops);

static struct fs_file_ops term_dev_raw_fs_file_ops = {
    .read = term_dev_raw_fs_file_read,
    .write = term_dev_raw_fs_file_write,
    .flush = term_dev_raw_fs_file_flush,
    // ...
};
FS_FILE_OPS_INIT_UNDEF(term_dev_raw_fs_file_ops);

int
term_dev_fs_node_init_raw(struct term_dev_fs_node *node)
{
    node->raw_vfs_node.fs_node_ops = &term_dev_raw_fs_node_ops;
    node->raw_vfs_node.fs_file_ops = &term_dev_raw_fs_file_ops;

    size_t inode;
    vfs_mount_insert_node(term_dev_fs_mount, &node->raw_vfs_node, &inode);

    return 0;
}
int
term_dev_fs_node_deinit_raw(struct term_dev_fs_node *node)
{
    vfs_mount_remove_node(term_dev_fs_mount, &node->raw_vfs_node);
    return 0;
}
