#ifndef __KANAWHA__FS_EXT2_GROUP_H__
#define __KANAWHA__FS_EXT2_GROUP_H__

#include <kanawha/spinlock.h>
#include <drivers/fs/ext2/ext2.h>
#include <drivers/fs/ext2/mount.h>

struct ext2_group
{
    int refs;

    struct ext2_mount *mnt;

    size_t index;

    spinlock_t desc_lock;
    struct ext2_group_desc desc;
    unsigned desc_dirty : 1;

    spinlock_t blk_lock;
    // Can be NULL if the blk_bitmap hasn't been accessed yet
    unsigned long *blk_bitmap;
    unsigned blk_dirty : 1;

    spinlock_t inode_lock;
    // Can be NULL if the inode_bitmap hasn't been accessed yet
    unsigned long *inode_bitmap;
    unsigned inode_dirty : 1;
};

struct ext2_group *
ext2_get_group(
        struct ext2_mount *mnt,
        size_t index);

int
ext2_put_group(
        struct ext2_mount *mnt,
        struct ext2_group *group);

int
ext2_flush_group(
        struct ext2_mount *mnt,
        struct ext2_group *group);

// inode Table
int
ext2_group_read_inode(
        struct ext2_group *group,
        size_t rel_index,
        struct ext2_inode *inode);

int
ext2_group_write_inode(
        struct ext2_group *group,
        size_t rel_index,
        struct ext2_inode *inode);

// Alloc/Free an inode/block
int
ext2_group_alloc_inode(
        struct ext2_group *group,
        size_t *abs_inode);
int
ext2_group_free_inode(
        struct ext2_group *group,
        size_t abs_inode);
int
ext2_group_alloc_block(
        struct ext2_group *group,
        size_t *abs_block);
int
ext2_group_free_block(
        struct ext2_group *group,
        size_t abs_block);

// Returns 0 on success, and sets value to 1 if the inode is allocated,
// and 0 if the inode is free.
int
ext2_group_inode_allocated(
        struct ext2_group *group,
        size_t block_index,
        int *value);

#endif
