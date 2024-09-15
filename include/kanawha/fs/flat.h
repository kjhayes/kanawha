#ifndef __KANAWHA__FS_FLAT_H__
#define __KANAWHA__FS_FLAT_H__

#include <kanawha/stree.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/ptree.h>
#include <kanawha/stree.h>
#include <kanawha/spinlock.h>

struct flat_node
{
    struct stree_node lookup_node;
    struct ptree_node inode_node;

    struct fs_node fs_node;
};

struct flat_mount
{
    spinlock_t lock;

    struct stree lookup_tree;
    struct ptree inode_tree;
    size_t num_nodes;

    struct flat_node root_node;

    struct fs_mount fs_mount;
};

struct flat_mount *
flat_mount_create(void);

int
flat_mount_destroy(
        struct flat_mount *mnt);

int
flat_mount_insert_node(
        struct flat_mount *mnt,
        struct flat_node *node,
        const char *name);

int
flat_mount_remove_node(
        struct flat_mount *mnt,
        struct flat_node *node);

struct flat_node *
flat_mount_get_node(
        struct flat_mount *mnt,
        const char *name);

#endif
