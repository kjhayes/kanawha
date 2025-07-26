

#include <kanawha/init.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <drivers/fs/ramfs/mount.h>

// Regular File fs_node

struct ramfs_node
{
    struct fs_node fs_node;
    struct ptree page_tree;
    size_t size;
};

struct fs_node_ops ramfs_node_ops =
{
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .symlink = fs_node_cannot_symlink,

    .lookup = fs_node_cannot_lookup,
    
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,

    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,

    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .flush = fs_node_cannot_flush,
    .flush_page = fs_node_cannot_flush_page,
};

struct fs_file_ops ramfs_file_ops =
{
    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,
    .seek = fs_file_cannot_seek,

    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

// Mount

static int
ramfs_mount_root_index(
        struct fs_mount *mnt,
        size_t *root_index)
{
    return -EUNIMPL;
}

static struct fs_node *
ramfs_mount_load_node(
        struct fs_mount *mnt,
        size_t node_index)
{
    return NULL;
}

static int
ramfs_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    return 0;
}

static struct fs_mount_ops
ramfs_mount_ops = {
    .root_index = ramfs_mount_root_index,
    .load_node = ramfs_mount_load_node,
    .unload_node = ramfs_mount_unload_node,
    .sync = fs_mount_nop_sync,
};

// ramfs FS type

static int
ramfs_type_mount_special(
        struct fs_type *type,
        const char *id,
        struct fs_mount **out)
{
    return -EUNIMPL;
}

static int
ramfs_type_unmount(
        struct fs_type *type,
        struct fs_mount *mnt)
{
    return -EUNIMPL;
}

struct fs_type ramfs_fs_type = {
    .mount_file = fs_type_cannot_mount_file,
    .mount_special = ramfs_type_mount_special,
    .unmount = ramfs_type_unmount,
};

static int
ramfs_register_fs_type(void)
{
    int res;
    res = register_fs_type(
            &ramfs_fs_type,
            "ramfs");
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(fs, ramfs_register_fs_type, "Registering RAMFS Filesystem");

