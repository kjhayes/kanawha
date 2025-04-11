
#include <kanawha/blk_dev.h>
#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>

static DECLARE_SPINLOCK(blk_dev_tree_lock);
static size_t num_blk_dev = 0;
static DECLARE_STREE(blk_dev_tree);

static struct flat_mount *blk_dev_fs_mount = NULL;
static struct fs_node_ops blk_dev_fs_node_ops;
static struct fs_file_ops blk_dev_fs_file_ops;

/*
 * Internal API(s)
 */

// Keeps a reference to "name"
int
register_blk_dev(struct blk_dev *blk,
        const char *name,
        struct blk_driver *driver)
{
    int res;

    spin_lock(&blk_dev_tree_lock);

    struct stree_node *existing = stree_get(&blk_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&blk_dev_tree_lock);
        return -EEXIST;
    }

    blk->driver = driver;
    dprintk("Registering blk_dev \"%s\"\n",
            name);

    blk->blk_dev_node.key = name;
    blk->flat_fs_node.fs_node.file_ops = &blk_dev_fs_file_ops;
    blk->flat_fs_node.fs_node.node_ops = &blk_dev_fs_node_ops;

    stree_insert(&blk_dev_tree, &blk->blk_dev_node);

    if(blk_dev_fs_mount != NULL) {
        res = flat_mount_insert_node(
                blk_dev_fs_mount,
                &blk->flat_fs_node,
                name);
        if(res) {
            stree_remove(&blk_dev_tree, name);
            spin_unlock(&blk_dev_tree_lock);
            return res;
        }
    }

    num_blk_dev++;

    spin_unlock(&blk_dev_tree_lock);

    return 0;
}

int
unregister_blk_dev(struct blk_dev *blk)
{
    return -EUNIMPL;
}

struct blk_dev *
find_blk_dev(const char *name)
{
    spin_lock(&blk_dev_tree_lock);
    struct stree_node *node = stree_get(&blk_dev_tree, name);
    spin_unlock(&blk_dev_tree_lock);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct blk_dev, blk_dev_node);
}

static int
blk_dev_init_fs_mount(void)
{
    int res;

    struct flat_mount *mnt;
    mnt = flat_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create flat mount!\n");
        return -ENOMEM;
    }

    spin_lock(&blk_dev_tree_lock);

    blk_dev_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&blk_dev_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct blk_dev *dev =
            container_of(node, struct blk_dev, blk_dev_node);
        res = flat_mount_insert_node(
                mnt,
                &dev->flat_fs_node,
                node->key);
        if(res) {
            spin_unlock(&blk_dev_tree_lock);
            return res;
        }
    }
    spin_unlock(&blk_dev_tree_lock);

    res = sysfs_register_mount(&blk_dev_fs_mount->fs_mount, "blkdev");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, blk_dev_init_fs_mount, "Registering blkdev Sysfs Mount");

static struct fs_node_ops blk_dev_fs_node_ops = {
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .lookup = fs_node_cannot_lookup,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .symlink = fs_node_cannot_symlink,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .flush_page = fs_node_cannot_flush_page,
};
static struct fs_file_ops blk_dev_fs_file_ops = {
    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .seek = fs_file_cannot_seek,
    .flush = fs_file_cannot_flush,
    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

