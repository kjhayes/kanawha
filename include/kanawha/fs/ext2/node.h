#ifndef __KANAWHA__FS_EXT2_NODE_H__
#define __KANAWHA__FS_EXT2_NODE_H__

#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/mount.h>

struct ext2_fs_node
{
    struct fs_node fs_node;
    struct ext2_mount *mount;

    struct ext2_inode inode;
    unsigned inode_dirty : 1;
};

extern struct fs_node_ops ext2_file_node_ops;
extern struct fs_file_ops ext2_file_file_ops;

extern struct fs_node_ops ext2_dir_node_ops;
extern struct fs_file_ops ext2_dir_file_ops;

int
ext2_fs_node_read_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn);

int
ext2_fs_node_write_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn);

int
ext2_fs_node_getattr(
        struct fs_node *node,
        int attr,
        size_t *value);

int
ext2_fs_node_setattr(
        struct fs_node *node,
        int attr,
        size_t value);

int
ext2_fs_node_flush(
        struct fs_node *node);

#endif
