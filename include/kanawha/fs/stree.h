#ifndef __KANAWHA__FS_STREE_H__
#define __KANAWHA__FS_STREE_H__

#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>

/*
 * stree Wrapper Mount
 */

struct stree_fs_node
{
    struct fs_node fs_node;
    struct stree_node stree_node;
    struct ptree_node index_node;
};

struct stree_fs_mount
{
    spinlock_t lock;
    struct fs_mount mount;

    struct stree_fs_node root_node;
    size_t num_children;

    struct stree node_tree;
    struct ptree node_index_tree;
};

int
stree_fs_mount_init(
        struct stree_fs_mount *mnt);

int
stree_fs_mount_deinit(
        struct stree_fs_mount *mnt);

struct fs_mount *
stree_fs_mount_get_mount(
        struct stree_fs_mount *mnt);

int
stree_fs_mount_insert(
        struct stree_fs_mount *mnt,
        struct stree_fs_node *node,
        const char *name);

int
stree_fs_mount_remove(
        struct stree_fs_mount *mnt,
        struct stree_fs_node *node);

#endif
