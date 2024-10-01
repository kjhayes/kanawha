#ifndef __KANAWHA__FS_EXT2_GROUP_H__
#define __KANAWHA__FS_EXT2_GROUP_H__

#include <kanawha/spinlock.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>

struct ext2_group
{
    int refs;

    struct ext2_mount *mnt;

    size_t index;

    spinlock_t desc_lock;
    struct ext2_group_desc desc;
    unsigned desc_dirty : 1;

    // Can be NULL if the blk_bitmap hasn't been accessed yet
    spinlock_t blk_lock;
    unsigned long *blk_bitmap;
    unsigned blk_dirty : 1;

    // Can be NULL if the inode_bitmap hasn't been accessed yet
    spinlock_t inode_lock;
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

// blk Bitmap
int
ext2_group_blk_bitmap_check(
        struct ext2_group *group,
        size_t rel_index,
        int *value);

int
ext2_group_blk_bitmap_alloc_specific(
        struct ext2_group *group,
        size_t rel_index);

int
ext2_group_blk_bitmap_free_specific(
        struct ext2_group *group,
        size_t rel_index);

// inode Bitmap
int
ext2_group_inode_bitmap_check(
        struct ext2_group *group,
        size_t rel_index,
        int *value);

int
ext2_group_inode_bitmap_alloc_specific(
        struct ext2_group *group,
        size_t rel_index);

int
ext2_group_inode_bitmap_free_specific(
        struct ext2_group *group,
        size_t rel_index);

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

#endif
