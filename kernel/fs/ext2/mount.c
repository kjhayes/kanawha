
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>

static struct fs_node *
ext2_mount_load_node(
        struct fs_mount *fs_mount,
        size_t node_index)
{
    return NULL;
}

static int
ext2_mount_unload_node(
        struct fs_mount *fs_mount,
        struct fs_node *fs_node)
{
    return -EUNIMPL;
}

int
ext2_mount_root_index(
        struct fs_mount *fs_mount,
        size_t *root_index)
{
    return -EUNIMPL;
}

static struct fs_mount_ops
ext2_mount_ops = {
    .load_node = ext2_mount_load_node,
    .unload_node = ext2_mount_unload_node,
    .root_index = ext2_mount_root_index,
};

static int
ext2_mount_file(
        struct fs_type *fs_type,
        struct fs_node *fs_node,
        struct fs_mount **out)
{
    int res;

    struct ext2_mount *mount = kmalloc(sizeof(struct ext2_mount));
    if(mount == NULL) {
        return -ENOMEM;
    }
    memset(mount, 0, sizeof(struct ext2_mount));

    res = fs_node_get(fs_node);
    if(res) {
        goto err1;
    }

    struct ext2_superblock superblock;
    ssize_t amount_to_read = sizeof(struct ext2_superblock);
    ssize_t amount_read;

    amount_read = fs_node_paged_read(
            fs_node,
            1024,
            &superblock,
            amount_to_read);
    if(amount_read < 0) {
        return amount_read;
    }

    if(amount_read < offsetof(struct ext2_superblock, extended)) {
        res = -EINVAL;
        goto err2;
    }

    if(superblock.version_major >= 1 &&
       amount_to_read < sizeof(struct ext2_superblock)) 
    {
        goto err2;
    }

    if(superblock.version_major < 1) {
        // Set some defaults for version 0
        superblock.extended.first_non_resv_inode = 11;
        superblock.extended.inode_size = 128;
    }

    printk("EXT2 Volume Version %u.%u\n", superblock.version_major, superblock.version_minor);
    printk("EXT2 Volume Blocks/Group: %u\n", superblock.blocks_per_group);
    printk("EXT2 Volume iNodes/Group: %u\n", superblock.inodes_per_group);
    printk("EXT2 Volume Blocks Total: %u\n", superblock.total_blocks);
    printk("EXT2 Volume iNodes Total: %u\n", superblock.total_inodes);

    if(superblock.blocks_per_group == 0) {
        eprintk("Invalid EXT2 Filesystem: blocks_per_group == 0\n");
        return -EINVAL;
    }
    if(superblock.inodes_per_group == 0) {
        eprintk("Invalid EXT2 Filesystem: inodes_per_group == 0\n");
        return -EINVAL;
    }

    uint32_t num_groups_from_blocks = superblock.total_blocks / superblock.blocks_per_group;
    num_groups_from_blocks += !!(superblock.total_blocks % superblock.blocks_per_group);
    uint32_t num_groups_from_inodes = superblock.total_inodes / superblock.inodes_per_group;
    num_groups_from_inodes += !!(superblock.total_inodes % superblock.inodes_per_group);

    printk("EXT2 Volume: Block Groups: %u (blk)\n", num_groups_from_blocks);
    printk("EXT2 Volume: Block Groups: %u (inode)\n", num_groups_from_inodes);

    if(num_groups_from_blocks != num_groups_from_inodes) {
        eprintk("Possibly Corrupt EXT2 Filesystem: # Block Groups Differs for Blocks and iNodes (blk=%u, inode=%u)\n",
                num_groups_from_blocks, num_groups_from_inodes);
        return -EINVAL;
    }

    return -EUNIMPL;

err2:
    fs_node_put(fs_node);
err1:
    kfree(mount);
    return res;
}

static int
ext2_unmount(
        struct fs_type *fs_type,
        struct fs_mount *fs_mount)
{
    return -EUNIMPL;
}

static struct fs_type
ext2_fs_type = {
    .mount_file = ext2_mount_file,
    .mount_special = fs_type_cannot_mount_special,
    .unmount = ext2_unmount,
};

static int
ext2_register_fs_type(void) {
    int res;
    res = register_fs_type(&ext2_fs_type, "ext2");
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(fs, ext2_register_fs_type, "Registering Ext2 Filesystem");

