
#include <kanawha/blk_dev.h>
#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
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
        struct blk_driver *driver,
        size_t num_sectors,
        order_t sector_order)
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

    blk->num_sectors = num_sectors;
    blk->sector_order = sector_order;

    blk->page_order = blk->sector_order;
    if(blk->page_order < PAGE_ALLOC_MIN_ORDER) {
        blk->page_order = PAGE_ALLOC_MIN_ORDER;
    }
    if(blk->page_order < VMEM_MIN_PAGE_ORDER) {
        blk->page_order = VMEM_MIN_PAGE_ORDER;
    }

    blk->sectors_per_page = 1ULL<<(blk->page_order - blk->sector_order);

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
blk_dev_find(const char *name)
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

static int
blk_dev_read_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    struct blk_dev *blk_dev =
        container_of(fs_node, struct blk_dev, flat_fs_node.fs_node);

    size_t start_sector = pfn * blk_dev->sectors_per_page;
    size_t sectors_to_read = blk_dev->sectors_per_page;
    size_t end_sector = start_sector + sectors_to_read;

    size_t extra_sectors = 0;
    if(end_sector > blk_dev->num_sectors) {
        extra_sectors = end_sector - blk_dev->num_sectors;
        sectors_to_read -= extra_sectors;
    }

    res = blk_dev_read(
            blk_dev,
            buffer,
            start_sector,
            sectors_to_read);
    if(res) {
        return res;
    }

    // Zero out any extra data
    for(size_t i = 0; i < extra_sectors; i++) {
        size_t offset = sectors_to_read<<blk_dev->sector_order;
        size_t extra_size = extra_sectors<<blk_dev->sector_order;
        memset(buffer + offset, 0, extra_size);
    }

    return 0;
}

static int
blk_dev_write_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    struct blk_dev *blk_dev =
        container_of(fs_node, struct blk_dev, flat_fs_node.fs_node);

    size_t start_sector = pfn * blk_dev->sectors_per_page;
    size_t sectors_to_write = blk_dev->sectors_per_page;
    size_t end_sector = start_sector + sectors_to_write;

    size_t extra_sectors = 0;
    if(end_sector > blk_dev->num_sectors) {
        extra_sectors = end_sector - blk_dev->num_sectors;
        sectors_to_write -= extra_sectors;
    }

    res = blk_dev_write(
            blk_dev,
            buffer,
            start_sector,
            sectors_to_write);
    if(res) {
        return res;
    }

    return 0;
}

static int
blk_dev_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    int res;

    struct blk_dev *blk_dev =
        container_of(fs_node, struct blk_dev, flat_fs_node.fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = (size_t)blk_dev->num_sectors << blk_dev->sector_order;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = blk_dev->page_order;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
blk_dev_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    return -EINVAL;
}

static struct fs_node_ops blk_dev_fs_node_ops =
{
    .read_page = blk_dev_read_page,
    .write_page = blk_dev_write_page,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,

    .getattr = blk_dev_getattr,
    .setattr = blk_dev_setattr,

    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .lookup = fs_node_cannot_lookup,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
};
static struct fs_file_ops blk_dev_fs_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,

    .flush = fs_file_paged_flush,

    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

