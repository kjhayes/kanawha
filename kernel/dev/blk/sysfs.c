
#include <kanawha/dev/blk.h>

#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/type.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/types.h>

struct blk_dev_fs_node
{
    struct blk_dev *dev;
    struct vfs_node vfs_node;

    order_t page_order;
    size_t sectors_per_page;
    size_t num_sectors;
    order_t sector_order;
};

static struct vfs_mount *blk_dev_fs_mount = NULL;
static struct fs_node_ops blk_dev_fs_node_ops;
static struct fs_file_ops blk_dev_fs_file_ops;

static int
blk_dev_fs_probe_blk_dev(struct blk_dev *dev)
{
    return 0;
}

static int
blk_dev_fs_receive_blk_dev(struct blk_dev *dev)
{
    int res;
    struct blk_dev_fs_node *node = kmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL)
    {
        return -ENOMEM;
    }
    node->dev = dev;

    node->num_sectors = blk_dev_num_sectors(dev);
    node->sector_order = blk_dev_sector_order(dev);

    node->page_order = node->sector_order;
    if(node->page_order < PAGE_ALLOC_MIN_ORDER)
    {
        node->page_order = PAGE_ALLOC_MIN_ORDER;
    }
    if(node->page_order < VMEM_MIN_PAGE_ORDER)
    {
        node->page_order = VMEM_MIN_PAGE_ORDER;
    }
    node->sectors_per_page = 1ULL << (node->page_order - node->sector_order);

    node->vfs_node.fs_node_ops = &blk_dev_fs_node_ops;
    node->vfs_node.fs_file_ops = &blk_dev_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(blk_dev_fs_mount,
                                              &node->vfs_node,
                                              blk_dev_get_name(dev));
    if(res)
    {
        kfree(node);
        return res;
    }

    return 0;
}

static int
blk_dev_fs_revoke_blk_dev(struct blk_dev *dev)
{
    eprintk("Tried to revoke blk device from blk_dev sysfs! (UNIMPL)\n");
    return -EUNIMPL;
}

static struct blk_dev_owner blk_dev_sysfs_owner = {
    .probe = blk_dev_fs_probe_blk_dev,
    .receive = blk_dev_fs_receive_blk_dev,
    .revoke = blk_dev_fs_revoke_blk_dev,
};

static int
blk_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        eprintk("Failed to create blk_dev VFS mount!\n");
        return -ENOMEM;
    }

    blk_dev_fs_mount = mnt;

    res = register_blk_dev_owner(&blk_dev_sysfs_owner);
    if(res)
    {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&blk_dev_fs_mount->fs_mount, "blkdev");
    if(res)
    {
        blk_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        unregister_blk_dev_owner(&blk_dev_sysfs_owner);
        return res;
    }

    return 0;
}
declare_init_desc(fs, blk_dev_init_fs_mount, "Registering blkdev Sysfs Mount");

static int
blk_dev_read_page(struct fs_node *fs_node,
                  void *buffer,
                  uintptr_t pfn,
                  unsigned long flags)
{
    int res;

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct blk_dev_fs_node *blk_dev_fs_node =
        container_of(vfs_node, struct blk_dev_fs_node, vfs_node);

    size_t start_sector = pfn * blk_dev_fs_node->sectors_per_page;
    size_t sectors_to_read = blk_dev_fs_node->sectors_per_page;
    size_t end_sector = start_sector + sectors_to_read;

    size_t extra_sectors = 0;

    if(end_sector > blk_dev_fs_node->num_sectors)
    {
        extra_sectors = end_sector - blk_dev_fs_node->num_sectors;
        sectors_to_read -= extra_sectors;
    }

    res = blk_dev_read(blk_dev_fs_node->dev,
                       buffer,
                       start_sector,
                       sectors_to_read);
    if(res)
    {
        return res;
    }

    // Zero out any extra data
    for(size_t i = 0; i < extra_sectors; i++)
    {
        size_t offset = sectors_to_read << blk_dev_fs_node->sector_order;
        size_t extra_size = extra_sectors << blk_dev_fs_node->sector_order;
        memset(buffer + offset, 0, extra_size);
    }

    return 0;
}

static int
blk_dev_write_page(struct fs_node *fs_node,
                   void *buffer,
                   uintptr_t pfn,
                   unsigned long flags)
{
    int res;

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct blk_dev_fs_node *blk_dev_fs_node =
        container_of(vfs_node, struct blk_dev_fs_node, vfs_node);

    size_t start_sector = pfn * blk_dev_fs_node->sectors_per_page;
    size_t sectors_to_write = blk_dev_fs_node->sectors_per_page;
    size_t end_sector = start_sector + sectors_to_write;

    size_t extra_sectors = 0;
    if(end_sector > blk_dev_fs_node->num_sectors)
    {
        extra_sectors = end_sector - blk_dev_fs_node->num_sectors;
        sectors_to_write -= extra_sectors;
    }

    res = blk_dev_write(blk_dev_fs_node->dev,
                        buffer,
                        start_sector,
                        sectors_to_write);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
blk_dev_getattr(struct fs_node *fs_node, int attr, size_t *value)
{
    int res;

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct blk_dev_fs_node *blk_dev_fs_node =
        container_of(vfs_node, struct blk_dev_fs_node, vfs_node);

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        *value = (size_t)blk_dev_fs_node->num_sectors
                 << blk_dev_fs_node->sector_order;
        break;
    case FS_NODE_ATTR_PAGE_ORDER:
        *value = blk_dev_fs_node->page_order;
        break;
    case FS_NODE_ATTR_SECTOR_ORDER:
        *value = blk_dev_fs_node->sector_order;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int
blk_dev_setattr(struct fs_node *fs_node, int attr, size_t value)
{
    return -EINVAL;
}

static struct fs_node_ops blk_dev_fs_node_ops = {
    .read_page = blk_dev_read_page,
    .write_page = blk_dev_write_page,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,

    .flush = fs_node_flush_nop,

    .getattr = blk_dev_getattr,
    .setattr = blk_dev_setattr,
};
FS_NODE_OPS_INIT_UNDEF(blk_dev_fs_node_ops);

static struct fs_file_ops blk_dev_fs_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,

    .flush = fs_file_paged_flush,
};
FS_FILE_OPS_INIT_UNDEF(blk_dev_fs_file_ops);
