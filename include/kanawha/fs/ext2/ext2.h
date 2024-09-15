#ifndef __KANAWHA__FS_EXT2_EXT2_H__
#define __KANAWHA__FS_EXT2_EXT2_H__

#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/type.h>
#include <kanawha/endian.h>

#define EXT2_SIGNATURE 0xEF53

#define EXT2_STATE_CLEAN  1
#define EXT2_STATE_ERRORS 2

#define EXT2_ERROR_IGNORE         1
#define EXT2_ERROR_MOUNT_READONLY 2
#define EXT2_ERROR_PANIC          3

#define EXT2_OS_LINUX    0
#define EXT2_OS_HURD     1
#define EXT2_OS_MASIX    2
#define EXT2_OS_FREEBSD  3
#define EXT2_OS_BSD_LITE 4

struct ext2_superblock {
    struct { // Present in all versions
      le32_t total_inodes;
      le32_t total_blocks;
      le32_t superuser_resv_blocks;
      le32_t blocks_unalloc;
      le32_t inodes_unalloc;
      le32_t superblock_index;
      le32_t log2_blksize_min_10;
      le32_t log2_fragsize_min_10;
      le32_t blocks_per_group;
      le32_t frag_per_group;
      le32_t inodes_per_group;
      le32_t posix_last_mount;
      le32_t posix_last_written;
      le16_t mounts_since_checked;
      le16_t mounts_allowed_without_check;
      le16_t signature;
      le16_t state;
      le16_t error_action;
      le16_t version_minor;
      le32_t posix_last_check;
      le32_t posix_min_check_interval;
      le32_t creator_os_id;
      le32_t version_major;
      le16_t uid_resv;
      le16_t gid_resv;
    };
    struct { // Major Version >= 1
      le32_t first_non_resv_inode;
      le16_t inode_size;
      le16_t this_block_group;
      le32_t optional_feat;
      le32_t required_feat;
      le32_t readonly_feat;
      char filesystem_id_cstr[16];
      char volume_name_cstr[16];
      char last_mount_path_cstr[64];
      le32_t compression_algs;
      uint8_t file_prealloc_blocks;
      uint8_t dir_prealloc_blocks;
      le16_t __unused;
      char journal_id_cstr[16];
      le32_t journal_inode;
      le32_t journal_device;
      le32_t orphan_inode_head;
    } extended;
} __attribute__((packed));

_Static_assert(sizeof(struct ext2_superblock) == 236, "struct ext2_superblock has incorrect size!");

#define EXT2_REQ_FEAT_COMPRESSION    (1ULL<<0)
#define EXT2_REQ_FEAT_TYPED_DIR      (1ULL<<1)
#define EXT2_REQ_FEAT_JOURNAL_REPLAY (1ULL<<2)
#define EXT2_REQ_FEAT_JOURNAL_DEVICE (1ULL<<3)

#define EXT2_READONLY_FEAT_SPARSE       (1ULL<<0)
#define EXT2_READONLY_FEAT_64_BIT_SIZE  (1ULL<<1)
#define EXT2_READONLY_FEAT_DIR_BIN_TREE (1ULL<<2)

struct ext2_mount {
    struct fs_mount fs_mount;
    struct fs_node *backing_node;
};

struct ext2_node {
    struct fs_node fs_node;
};

#endif
