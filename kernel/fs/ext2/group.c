
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/bitmap.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>
#include <kanawha/fs/ext2/group.h>
#include <kanawha/string.h>

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

    dprintk("ext2_mount_read_group_desc(mnt=%p, grp_index=0x%lx) desc_offset=%p\n",
            mnt, grp_index, desc_offset);
    res = fs_node_paged_read(
            mnt->backing_node,
            desc_offset,
            desc,
            sizeof(struct ext2_group_desc),
            0);
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
            sizeof(struct ext2_group_desc),
            0);
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

        dprintk("Loaded EXT2 Group 0x%llx Descriptor (mnt=%p)\n",
                (ull_t)index, mnt);
        dprintk("\tFree inodes: 0x%llx\n", (ull_t)group->desc.free_inodes_count);
        dprintk("\tFree blocks: 0x%llx\n", (ull_t)group->desc.free_blocks_count);
        dprintk("\tinode Bitmap Block: 0x%llx\n", (ull_t)group->desc.inode_bitmap);
        dprintk("\tblock Bitmap Block: 0x%llx\n", (ull_t)group->desc.block_bitmap);
        dprintk("\tinode Table Block: 0x%llx\n", (ull_t)group->desc.inode_table);

        mnt->group_cache[index] = group;
    } else {
        mnt->group_cache[index]->refs++;
    }

    spin_unlock(&mnt->group_cache_lock);

    DEBUG_ASSERT(mnt->group_cache[index]->mnt == mnt);
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
    if(grp->blk_bitmap == NULL) {
        spin_unlock(&grp->blk_lock);
        return -ENOMEM;
    }

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.block_bitmap, grp->mnt->block_size);

    res = fs_node_paged_read(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->blk_bitmap,
            grp->mnt->block_size,
            0);
    if(res) {
        kfree(grp->blk_bitmap);
        grp->blk_bitmap = NULL;
        spin_unlock(&grp->blk_lock);
        return res;
    }

    dprintk("Read Block Group %ld's Block Bitmap: 0x%llx\n",
            grp->index, *(uint64_t*)(grp->blk_bitmap));

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
            grp->mnt->block_size,
            0);
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
    if(grp->inode_bitmap == NULL) {
        spin_unlock(&grp->inode_lock);
        return -ENOMEM;
    }

    size_t bitmap_offset =
        EXT2_BLOCK_OFFSET(grp->desc.inode_bitmap, grp->mnt->block_size);

    res = fs_node_paged_read(
            grp->mnt->backing_node,
            bitmap_offset,
            grp->inode_bitmap,
            grp->mnt->block_size,
            0);
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
            grp->mnt->block_size,
            0);
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

    dprintk("ext2_put_group(0x%lx)\n",
            (ul_t)group->index);

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

    DEBUG_ASSERT(KERNEL_ADDR(group));
    DEBUG_ASSERT(KERNEL_ADDR(group->mnt));

    if(rel_index > group->mnt->blks_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_blk_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->blk_lock);
    DEBUG_ASSERT(KERNEL_ADDR(group->blk_bitmap));
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

    spin_lock(&group->desc_lock);
    group->desc.free_blocks_count++;
    group->desc_dirty = 1;
    spin_unlock(&group->desc_lock);

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

    DEBUG_ASSERT(KERNEL_ADDR(group));
    DEBUG_ASSERT(KERNEL_ADDR(group->mnt));

    if(rel_index > group->mnt->inodes_per_group) {
        return -EINVAL;
    }

    res = ext2_group_populate_inode_bitmap(group);
    if(res) {
        return res;
    }
    DEBUG_ASSERT(KERNEL_ADDR(group->inode_bitmap));

    spin_lock(&group->inode_lock);
    *value = bitmap_check(group->inode_bitmap, rel_index);
    spin_unlock(&group->inode_lock);

    dprintk("ext2_group_inode_bitmap_check DONE\n");
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

    spin_lock(&group->desc_lock);
    group->desc.free_inodes_count++;
    group->desc_dirty = 1;
    spin_unlock(&group->desc_lock);

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

    dprintk("inode_size = %p, local_index = %p\n", group->mnt->inode_size, rel_index);

    dprintk("fs_node_paged_read(offset=%p, size=%p)\n",
            inode_offset, sizeof(struct ext2_group_desc));

    size_t size = group->mnt->inode_size < sizeof(struct ext2_inode) ? group->mnt->inode_size : sizeof(struct ext2_inode);

    res = fs_node_paged_read(
            group->mnt->backing_node,
            inode_offset,
            inode,
            size,
            0);
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

    size_t size = group->mnt->inode_size < sizeof(struct ext2_inode) ? group->mnt->inode_size : sizeof(struct ext2_inode);

    res = fs_node_paged_write(
            group->mnt->backing_node,
            inode_offset,
            inode,
            size,
            0);
    if(res) {
        return res;
    }

    return 0;
}

int
ext2_group_alloc_inode(
        struct ext2_group *group,
        size_t *inode_out)
{
    int res;

    res = ext2_group_populate_inode_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->inode_lock);

    int found = 0;

    size_t bit;
    size_t base_inode = (group->index * group->mnt->inodes_per_group)+1;
    if(base_inode < group->mnt->resv_inodes) {
        bit = group->mnt->resv_inodes - (base_inode-1);
    } else {
        bit = 0;
    }

    for(; bit < group->mnt->inodes_per_group; bit++) {
        // Linear scan of bits (not ideal but we'll keep it simple for now)
        if(bitmap_check(group->inode_bitmap, bit)) {
            continue;
        }
        found = 1;
        bitmap_set(group->inode_bitmap, bit);
        break;
    }

    if(found == 0) {
         // Invalid inode number (to be safe)
        *inode_out = 0;
        spin_unlock(&group->inode_lock);
        return -ENOMEM;
    }

    *inode_out = (group->index*group->mnt->inodes_per_group) + (bit + 1);

    // Clear the inode
    struct ext2_inode inode;
    res = ext2_group_read_inode(
            group,
            bit,
            &inode);
    if(res) {
        spin_unlock(&group->inode_lock);
        return res;
    }

    // Clear the inode
    memset(&inode, 0, sizeof(struct ext2_inode));

    res = ext2_group_write_inode(
            group,
            bit,
            &inode);
    if(res) {
        spin_unlock(&group->inode_lock);
        return res;
    }

    spin_unlock(&group->inode_lock);

    spin_lock(&group->desc_lock);
    group->desc.free_inodes_count--;
    group->desc_dirty = 1;
    spin_unlock(&group->desc_lock);

    return 0;
}

int
ext2_group_alloc_block(
        struct ext2_group *group,
        size_t *blk_out)
{
    int res;

    res = ext2_group_populate_blk_bitmap(group);
    if(res) {
        return res;
    }

    spin_lock(&group->blk_lock);

    // TODO: ensure this is little endian
    size_t bit = bitmap_find_clear_range(group->blk_bitmap, group->mnt->blks_per_group, 1);
    if(bit < 0 || bit >= group->mnt->blks_per_group) {
        spin_unlock(&group->blk_lock);
        return -ENOMEM;
    }

    bitmap_set(group->blk_bitmap, bit);
    *blk_out = (group->index*group->mnt->blks_per_group) + bit;

    spin_unlock(&group->blk_lock);

    spin_lock(&group->desc_lock);
    group->desc.free_blocks_count--;
    group->desc_dirty = 1;
    spin_unlock(&group->desc_lock);

    return 0;
}

