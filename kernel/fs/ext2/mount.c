
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>
#include <kanawha/fs/ext2/node.h>
#include <kanawha/fs/ext2/dir.h>
#include <kanawha/fs/ext2/group.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>

int
ext2_mount_read_inode(
        struct ext2_mount *mnt,
        size_t inode_index,
        struct ext2_inode *inode_data)
{
    int res;

    size_t group_index = (inode_index-1) / mnt->inodes_per_group;
    size_t index_in_group = (inode_index-1) % mnt->inodes_per_group;

    struct ext2_group *group = ext2_get_group(mnt, group_index);
    if(group == NULL) {
        return -ENXIO;
    }
    DEBUG_ASSERT(group->mnt == mnt);

    res = ext2_group_read_inode(
            group,
            index_in_group,
            inode_data);
    if(res) {
        ext2_put_group(mnt, group);
        return res;
    }

    ext2_put_group(mnt, group);
    return 0;
}

int
ext2_mount_write_inode(
        struct ext2_mount *mnt,
        size_t inode_index,
        struct ext2_inode *inode_data)
{
    int res;

    size_t group_index = (inode_index-1) / mnt->inodes_per_group;
    size_t index_in_group = (inode_index-1) % mnt->inodes_per_group;

    struct ext2_group *group = ext2_get_group(mnt, group_index);
    if(group == NULL) {
        return -ENXIO;
    }
    DEBUG_ASSERT(group->mnt == mnt);

    res = ext2_group_write_inode(
            group,
            index_in_group,
            inode_data);
    if(res) {
        ext2_put_group(mnt, group);
        return res;
    }

    ext2_put_group(mnt, group);
    return 0;
}

static struct fs_node *
ext2_mount_load_node(
        struct fs_mount *fs_mount,
        size_t node_index)
{
    int res;

    struct ext2_mount *mnt =
        container_of(fs_mount, struct ext2_mount, fs_mount);

    printk("ext2_mount_load_node (inode=0x%lx)\n", node_index);

    if(node_index >= mnt->num_inodes) {
        return NULL;
    }

    size_t group_index = (node_index-1) / mnt->inodes_per_group;
    size_t index_in_group = (node_index-1) % mnt->inodes_per_group;

    struct ext2_group *group = ext2_get_group(mnt, group_index);
    if(group == NULL) {
        return NULL;
    }
    DEBUG_ASSERT(group->mnt == mnt);

    struct ext2_fs_node *node = kmalloc(sizeof(struct ext2_fs_node));
    if(node == NULL) {
        ext2_put_group(mnt, group);
        return NULL;
    }

    node->mount = mnt;
    spinlock_init(&node->lock);

    int is_inode_alloced;
    res = ext2_group_inode_bitmap_check(group, index_in_group, &is_inode_alloced);
    if(res) {
        eprintk("ext2_mount_load_node: Failed to read from block group inode bitmap! (err=%s)\n",
                errnostr(res));
        ext2_put_group(mnt, group);
        kfree(node);
        return NULL;
    }
    else if(!is_inode_alloced) {
        eprintk("ext2_mount_load_node: Tried to load unallocated node 0x%llx!\n",
                (ull_t)node_index);
        ext2_put_group(mnt, group);
        kfree(node);
        return NULL;
    }

    res = ext2_group_read_inode(
            group,
            index_in_group,
            &node->inode);
    if(res) {
        ext2_put_group(mnt, group);
        kfree(node);
        return NULL;
    }
    node->inode_dirty = 0;

    // TODO: Switch on inode type,
    // and assign the file_ops and inode_ops

    printk("inode->mode = 0x%x\n", node->inode.mode);

    switch(node->inode.mode & 0xF000) {
      case 0x8000:
        node->fs_node.file_ops = &ext2_file_file_ops;
        node->fs_node.node_ops = &ext2_file_node_ops;
        break;
      case 0x4000:
        node->fs_node.file_ops = &ext2_dir_file_ops;
        node->fs_node.node_ops = &ext2_dir_node_ops;
        break;
      default:
        ext2_put_group(mnt, group);
        kfree(node);
        return NULL;
    }

    printk("EXT2 Loaded Node (0x%llx)\n",
            (ull_t)node_index);

    ext2_put_group(mnt, group);

    return &node->fs_node;
}

static int
ext2_mount_unload_node(
        struct fs_mount *fs_mount,
        struct fs_node *fs_node)
{
    int res;

    struct ext2_mount *mnt =
        container_of(fs_mount, struct ext2_mount, fs_mount);
    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    if(node->inode_dirty) {
        size_t grp_index = ext2_fs_node_to_group_num(node);
        struct ext2_group *group = ext2_get_group(mnt, grp_index);
        if(group == NULL) {
            eprintk("Could not get EXT2 Block Group while unloading inode!\n");
            res = -EINVAL;
            goto err;
        }
        ext2_group_write_inode(group, (node->fs_node.cache_node.key-1)%mnt->inodes_per_group, &node->inode);
        node->inode_dirty = 0;
    }

    kfree(node);

    return 0;

err:
    return res;
}

int
ext2_mount_root_index(
        struct fs_mount *fs_mount,
        size_t *root_index)
{
    *root_index = EXT2_ROOT_INODE;
    return 0;
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

    res = fs_node_get(fs_node);
    if(res) {
        goto err1;
    }

    struct ext2_superblock superblock;

    ssize_t amount_to_read = sizeof(struct ext2_superblock);
    ssize_t amount_read;

    res = fs_node_paged_read(
            fs_node,
            EXT2_SUPERBLOCK_OFFSET,
            &superblock,
            amount_to_read,
            0);
    if(res) {
        eprintk("Invalid EXT2 Filesystem: failed to read minimum sized ext2 superblock!\n");
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
        res = -EINVAL;
        goto err2;
    }
    if(superblock.inodes_per_group == 0) {
        eprintk("Invalid EXT2 Filesystem: inodes_per_group == 0\n");
        res = -EINVAL;
        goto err2;
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
        res = -EINVAL;
        goto err2;
    }

    struct ext2_mount *mnt = kmalloc(sizeof(struct ext2_mount));
    if(mnt == NULL) {
        res = -ENOMEM;
        goto err2;
    }
    memset(mnt, 0, sizeof(struct ext2_mount));

    mnt->backing_node = fs_node;
    res = init_fs_mount_struct(
            &mnt->fs_mount,
            &ext2_mount_ops);
    if(res) {
        eprintk("EXT2: Failed to initialize mount struct! (err=%s)\n",
                errnostr(res));
        goto err3;
    }

    mnt->num_blocks = superblock.total_blocks;
    mnt->num_inodes = superblock.total_inodes;
    mnt->resv_inodes = superblock.extended.first_non_resv_inode;

    mnt->first_data_block = superblock.superblock_index;

    mnt->num_groups = num_groups_from_blocks;
    mnt->group_cache = kmalloc(sizeof(struct ext2_group*) * mnt->num_groups);
    if(mnt->group_cache == NULL) {
        res = -ENOMEM;
        goto err3;
    }
    memset(mnt->group_cache, 0, sizeof(struct ext2_group*) * mnt->num_groups);

    spinlock_init(&mnt->group_cache_lock);

    mnt->blks_per_group = superblock.blocks_per_group;
    mnt->inodes_per_group = superblock.inodes_per_group;

    mnt->block_order = 10 + superblock.log2_blksize_min_10;
    mnt->block_size = 1024 << superblock.log2_blksize_min_10;
    mnt->frag_size = 1024 << superblock.log2_fragsize_min_10;
    mnt->inode_size = superblock.extended.inode_size;

    printk("EXT2 Volume: Block Size 0x%llx\n", (ull_t)mnt->block_size);
    printk("EXT2 Volume: Fragment Size 0x%llx\n", (ull_t)mnt->frag_size);

    *out = &mnt->fs_mount;

    return 0;

err3:
    kfree(mnt);
err2:
    fs_node_put(fs_node);
err1:
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

int
ext2_mount_alloc_inode(
        struct ext2_mount *mnt,
        size_t pref_group,
        size_t *inode_out)
{
    int res;

    struct ext2_group *group;
    group = ext2_get_group(mnt, pref_group);
    if(group != NULL) {
        res = ext2_group_alloc_inode(group, inode_out);  
        ext2_put_group(mnt, group);
        if(!res) {
            return 0;
        }
    }

    for(size_t group_id = 0; group_id < mnt->num_groups; group_id++) {
        if(group_id == pref_group) {
            continue;
        }
        group = ext2_get_group(mnt, group_id);
        res = ext2_group_alloc_inode(group, inode_out);  
        ext2_put_group(mnt, group);
        if(!res) {
            return 0;
        }
    }
    return -ENOMEM;
}

int
ext2_mount_free_inode(
        struct ext2_mount *mnt,
        size_t inode)
{
    int res;

    size_t grp_index = (inode-1) / mnt->inodes_per_group;

    struct ext2_group *group;
    group = ext2_get_group(mnt, grp_index);
    if(group == NULL) {
        return -ENXIO;
    }

    ext2_group_inode_bitmap_free_specific(group, (inode-1) % mnt->inodes_per_group);

    ext2_put_group(mnt, group);

    return 0;
}

int
ext2_mount_alloc_block(
        struct ext2_mount *mnt,
        size_t pref_group,
        size_t *block_out)
{
    int res;

    struct ext2_group *group;
    group = ext2_get_group(mnt, pref_group);
    if(group != NULL) {
        res = ext2_group_alloc_block(group, block_out);  
        ext2_put_group(mnt, group);
        if(!res) {
            return 0;
        }
    }

    for(size_t group_id = 0; group_id < mnt->num_groups; group_id++) {
        if(group_id == pref_group) {
            continue;
        }
        group = ext2_get_group(mnt, group_id);
        res = ext2_group_alloc_block(group, block_out);  
        ext2_put_group(mnt, group);
        if(!res) {
            return 0;
        }
    }
    return -ENOMEM;
}

int
ext2_mount_free_block(
        struct ext2_mount *mnt,
        size_t block)
{
    int res;

    size_t grp_index = block / mnt->blks_per_group;

    struct ext2_group *group;
    group = ext2_get_group(mnt, grp_index);
    if(group == NULL) {
        return -ENXIO;
    }

    ext2_group_blk_bitmap_free_specific(group, block % mnt->blks_per_group);

    ext2_put_group(mnt, group);

    return 0;
}

