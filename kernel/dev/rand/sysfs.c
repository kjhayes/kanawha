
#include <kanawha/dev/rand.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct rand_dev_fs_node {
    struct vfs_node vfs_node;
    struct rand_dev *dev;
};

static struct vfs_mount *rand_dev_fs_mount = NULL;
static struct rand_dev_hook *rand_dev_fs_hook = NULL;

static ssize_t 
rand_dev_fs_file_read(
        struct file *file,
        void * buf,
        ssize_t buflen,
        unsigned long flags
        )
{
    int res;

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct rand_dev_fs_node *rdfs =
        container_of(node, struct rand_dev_fs_node, vfs_node.fs_node);

    if(buflen <= 0) {
        return -EINVAL;
    }

    res = rand_dev_read(
            rdfs->dev,
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
    .poll = fs_file_cannot_poll,
};


static void
rand_dev_fs_on_register(
        struct rand_dev *dev)
{
    int res;

    struct rand_dev_fs_node *rdfs = kmalloc(sizeof(*rdfs));
    if(rdfs == NULL) {
        return;
    }
    memset(rdfs, 0, sizeof(*rdfs));

    rdfs->dev = dev;

    rdfs->vfs_node.fs_node.unload = NULL;
    rdfs->vfs_node.fs_node.node_ops = &rand_dev_fs_node_ops;
    rdfs->vfs_node.fs_node.file_ops = &rand_dev_fs_file_ops;

    size_t inode;

    res = vfs_mount_insert_node(
            rand_dev_fs_mount,
            &rdfs->vfs_node,
            &inode);
    if(res) {
        return;
    }

    res = vfs_mount_link_root(
            rand_dev_fs_mount,
            dev->rand_dev_node.key,
            inode);
    if(res) {
        vfs_mount_remove_node(
                rand_dev_fs_mount,
                &rdfs->vfs_node);
        return;
    }
}

static void
rand_dev_fs_on_unregister(
        struct rand_dev *dev)
{
    panic("Tried to unregister a rand_dev from sysfs! (UNIMPL)\n");
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

    rand_dev_fs_mount = mnt;

    struct rand_dev_hook *hook;
    hook = hook_rand_dev_registry(
            rand_dev_fs_on_register,
            rand_dev_fs_on_unregister);
    if(hook == NULL) {
        rand_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    rand_dev_fs_hook = hook;

    res = sysfs_register_mount(
            &rand_dev_fs_mount->fs_mount,
            "randdev");
    if(res) {
        rand_dev_fs_hook = NULL;
        unhook_rand_dev_registry(hook);
        rand_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    return 0;
}

declare_init_desc(fs, rand_dev_init_fs_mount, "Registering randdev Sysfs Mount");
