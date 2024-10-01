
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/bitmap.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>
#include <kanawha/fs/ext2/group.h>

static int
ext2_mount_read_group_desc(
        struct ext2_mount *mnt,
        size_t grp_index,
        struct ext2_group_desc *desc)
{
    int res;

    size_t table_block_index = mnt->block_size <= 1024 ? 2 : 1;
    size_t desc_list_offset = EXT2_BLOCK_OFFSET(table_block_index, mnt->block_size);
    size_t desc_offset = desc_list_offset + (sizeof(struct ext2_group_desc) * grp_index);

    res = fs_node_paged_read(
            mnt->backing_node,
            desc_offset,
            desc,
            sizeof(struct ext2_group_desc));
    if(res) {
        return res;
    }

    return 0;
}

static int
ext2_mount_write_group_desc(
        struct ext2_mount *mnt,
        size_t grp_index,
        struct ext2_group_desc *desc)
{
    int res;

    size_t table_block_index = mnt->block_size <= 1024 ? 2 : 1;
    size_t desc_list_offset = EXT2_BLOCK_OFFSET(table_block_index, mnt->block_size);
    size_t desc_offset = desc_list_offset + (sizeof(struct ext2_group_desc) * grp_index);

    res = fs_node_paged_write(
            mnt->backing_node,
            desc_offset,
            desc,
            sizeof(struct ext2_group_desc));
    if(res) {
        return res;
    }

    return 0;
}

struct ext2_group *
ext2_get_group(
        struct ext2_mount *mnt,
        size_t index)
{
    int res;

    if(index >= mnt->num_groups) {
        return NULL;
    }

    spin_lock(&mnt->group_cache_lock);

    if(mnt->group_cache[index] == NULL) {
        struct ext2_group *group = kmalloc(sizeof(struct ext2_group));
        if(group == NULL) {
            spin_unlock(&mnt->group_cache_lock);
            return NULL;
        }

        group->refs = 1;
        group->index = index;
        group->mnt = mnt;

        group->desc_dirty = 0;
        group->blk_dirty = 0;
        group->inode_dirty = 0;

        spinlock_init(&group->desc_lock);
        spinlock_init(&group->blk_lock);
        spinlock_init(&group->inode_lock);

        group->blk_bitmap = NULL;
        group->inode_bitmap = NULL;

        res = ext2_mount_read_group_desc(
                mnt,
                index,
                &group->desc);
        if(res) {
            kfree(group);
            spin_unlock(&mnt->group_cache_lock);
            return NULL;
        }

        printk("Loaded EXT2 Group 0x%llx Descriptor\n",
                (ull_t)index);
        printk("\tFree inodes: 0x%llx\n", (ull_t)group->desc.free_inodes_count);
        printk("\tFree blocks: 0x%llx\n", (ull_t)group->desc.free_blocks_count);
        printk("\tinode Bitmap Block: 0x%llx\n", (ull_t)group->desc.inode_bitmap);
        printk("\tblock Bitmap Block: 0x%llx\n", (ull_t)group->desc.block_bitmap);
        printk("\tinode Table Block: 0x%llx\n", (ull_t)group->desc.inode_table);

        mnt->group_cache[index] = group;
    } 

    spin_unlock(&mnt->group_cache_lock);

    return mnt->group_cache[index];
}

static int
ext2_group_populate_blk_bitmap(
        struct ext2_group *grp)
{
    int res;

    if(grp->blk_bitmap != NULL) {
        return 0;
    }

    spin_lock(&grp->blk_lock);

    if(grp->blk_bitmap != NULL) {
        spin_unlock(&grp->blk_lock);
        return 0;
    }

    grp->blk_bitmap = kmalloc(grp->mnt->block_size);

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.block_bitmap, grp->mnt->block_size);

    res = fs_node_paged_read(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->blk_bitmap,
            grp->mnt->block_size);
    if(res) {
        kfree(grp->blk_bitmap);
        grp->blk_bitmap = NULL;
        spin_unlock(&grp->blk_lock);
        return res;
    }

    grp->blk_dirty = 0;

    spin_unlock(&grp->blk_lock);
    return 0;
}

static int
ext2_group_flush_blk_bitmap(
        struct ext2_group *grp)
{
    int res;

    if(grp->blk_bitmap == NULL) {
        return 0;
    }

    spin_lock(&grp->blk_lock);

    if(grp->blk_bitmap == NULL) {
        spin_unlock(&grp->blk_lock);
        return 0;
    }

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.block_bitmap, grp->mnt->block_size);

    res = fs_node_paged_write(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->blk_bitmap,
            grp->mnt->block_size);
    if(res) {
        spin_unlock(&grp->blk_lock);
        return res;
    }

    grp->blk_dirty = 0;

    spin_unlock(&grp->blk_lock);
    return 0;
}

static int
ext2_group_populate_inode_bitmap(
        struct ext2_group *grp)
{
    int res;

    if(grp->inode_bitmap != NULL) {
        return 0;
    }

    spin_lock(&grp->inode_lock);

    if(grp->inode_bitmap != NULL) {
        spin_unlock(&grp->inode_lock);
        return 0;
    }

    grp->inode_bitmap = kmalloc(grp->mnt->block_size);

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.inode_bitmap, grp->mnt->block_size);

    res = fs_node_paged_read(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->inode_bitmap,
            grp->mnt->block_size);
    if(res) {
        kfree(grp->inode_bitmap);
        grp->inode_bitmap = NULL;
        spin_unlock(&grp->inode_lock);
        return res;
    }

    grp->inode_dirty = 0;

    spin_unlock(&grp->inode_lock);
    return 0;
}

static int
ext2_group_flush_inode_bitmap(
        struct ext2_group *grp)
{
    int res;

    if(grp->inode_bitmap == NULL) {
        return 0;
    }

    spin_lock(&grp->inode_lock);

    if(grp->inode_bitmap == NULL) {
        spin_unlock(&grp->inode_lock);
        return 0;
    }

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.inode_bitmap, grp->mnt->block_size);

    res = fs_node_paged_write(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->inode_bitmap,
            grp->mnt->block_size);
    if(res) {
        spin_unlock(&grp->inode_lock);
        return res;
    }

    grp->inode_dirty = 0;

    spin_unlock(&grp->inode_lock);
    return 0;
}

int
ext2_put_group(
        struct ext2_mount *mnt,
        struct ext2_group *group)
{
    int res;

    spin_lock(&mnt->group_cache_lock);

    group->refs--;
    if(group->refs <= 0) {

        // Flush any dirty data to disk
        if(group->desc_dirty) {
            res = ext2_mount_write_group_desc(
                    mnt,
                    group->index,
                    &group->desc);
            if(res) {
                eprintk("Failed to write EXT2 group descriptor back to disk! (err=%s)\n",
                        errnostr(res));
                // We'll just have to continue :(
                // (Once we setup caching fully we could leave it in the cache for a bit
                //  and defer dealing with this though)
            }
        }

        // Write the blk bitmap out to disk
        res = ext2_group_flush_blk_bitmap(group);
        if(res) {
            eprintk("Failed to write EXT2 group block bitmap back to disk! (err=%s)\n",
                    errnostr(res));
        }

        // Write the inode bitmap out to disk
        res = ext2_group_flush_inode_bitmap(group);
        if(res) {
            eprintk("Failed to write EXT2 group inode bitmap back to disk! (err=%s)\n",
                    errnostr(res));
        }

        // Free our data structures
        if(group->blk_bitmap) {
            kfree(group->blk_bitmap);
        }
        if(group->inode_bitmap) {
            kfree(group->inode_bitmap);
        }

        mnt->group_cache[group->index] = NULL;
        kfree(group);
    }

    spin_unlock(&mnt->group_cache_lock);

    return 0;
}

// blk Bitmap
int
ext2_group_blk_bitmap_check(
        struct ext2_group *group,
        size_t rel_index,
        int *value)
{
    int res;
    if(rel_index > group->mnt->blks_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_blk_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->blk_lock);
    *value = bitmap_check(group->blk_bitmap, rel_index);
    spin_unlock(&group->blk_lock);

    return 0;
}

int
ext2_group_blk_bitmap_alloc_specific(
        struct ext2_group *group,
        size_t rel_index)
{
    int res;
    if(rel_index > group->mnt->blks_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_blk_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->blk_lock);
    bitmap_set(group->blk_bitmap, rel_index);
    group->blk_dirty = 1;
    spin_unlock(&group->blk_lock);

    return 0;
}

int
ext2_group_blk_bitmap_free_specific(
        struct ext2_group *group,
        size_t rel_index)
{
    int res;
    if(rel_index > group->mnt->blks_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_blk_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->blk_lock);
    bitmap_clear(group->blk_bitmap, rel_index);
    group->blk_dirty = 1;
    spin_unlock(&group->blk_lock);

    return 0;
}

// inode Bitmap
int
ext2_group_inode_bitmap_check(
        struct ext2_group *group,
        size_t rel_index,
        int *value)
{
    int res;
    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_inode_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->inode_lock);
    *value = bitmap_check(group->inode_bitmap, rel_index);
    spin_unlock(&group->inode_lock);

    return 0;
}

int
ext2_group_inode_bitmap_alloc_specific(
        struct ext2_group *group,
        size_t rel_index)
{
    int res;
    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_inode_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->inode_lock);
    bitmap_set(group->inode_bitmap, rel_index);
    group->inode_dirty = 1;
    spin_unlock(&group->inode_lock);

    return 0;
}

int
ext2_group_inode_bitmap_free_specific(
        struct ext2_group *group,
        size_t rel_index)
{
    int res;
    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_inode_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->inode_lock);
    bitmap_clear(group->inode_bitmap, rel_index);
    group->inode_dirty = 1;
    spin_unlock(&group->inode_lock);

    return 0;
}

int
ext2_group_read_inode(
        struct ext2_group *group,
        size_t rel_index,
        struct ext2_inode *inode)
{
    int res;
    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    size_t table_offset =
        EXT2_BLOCK_OFFSET(group->desc.inode_table, group->mnt->block_size);
    size_t inode_offset = table_offset + (group->mnt->inode_size * rel_index);

    printk("inode_size = %p, local_index = %p\n", group->mnt->inode_size, rel_index);

    printk("fs_node_paged_read(offset=%p, size=%p)\n",
            inode_offset, sizeof(struct ext2_group_desc));

    res = fs_node_paged_read(
            group->mnt->backing_node,
            inode_offset,
            inode,
            group->mnt->inode_size);
    if(res) {
        return res;
    }

    return 0;
}

int
ext2_group_write_inode(
        struct ext2_group *group,
        size_t rel_index,
        struct ext2_inode *inode)
{
    int res;
    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    size_t table_offset =
        EXT2_BLOCK_OFFSET(group->desc.inode_table, group->mnt->block_size);
    size_t inode_offset = table_offset + (group->mnt->inode_size * rel_index);

    res = fs_node_paged_write(
            group->mnt->backing_node,
            inode_offset,
            inode,
            group->mnt->inode_size);
    if(res) {
        return res;
    }

    return 0;
}

