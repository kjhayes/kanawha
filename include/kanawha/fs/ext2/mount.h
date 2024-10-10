#ifndef __KANAWHA__FS_EXT2_MOUNT_H__
#define __KANAWHA__FS_EXT2_MOUNT_H__

#include <kanawha/fs/ext2/ext2.h>

struct ext2_mount {
    struct fs_mount fs_mount;
    struct fs_node *backing_node;

    size_t num_blocks;
    size_t num_inodes;
    size_t resv_inodes;

    spinlock_t group_cache_lock;
    size_t num_groups;
    struct ext2_group **group_cache;

    size_t blks_per_group;
    size_t inodes_per_group;

    order_t block_order;
    size_t block_size;
    size_t frag_size;
    size_t inode_size;
};

int
ext2_mount_alloc_inode(
        struct ext2_mount *mnt,
        size_t pref_group,
        size_t *inode_out);
int
ext2_mount_free_inode(
        struct ext2_mount *mnt,
        size_t inode);

int
ext2_mount_read_inode(
        struct ext2_mount *mnt,
        size_t inode_index,
        struct ext2_inode *inode_data);
int
ext2_mount_write_inode(
        struct ext2_mount *mnt,
        size_t inode_index,
        struct ext2_inode *inode_data);

#endif
