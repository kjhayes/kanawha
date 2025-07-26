#ifndef __KANAWHA__FS_SYS_VFS_H__
#define __KANAWHA__FS_SYS_VFS_H__

#include <kanawha/fs/node.h>

#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/file.h>

struct vfs_node
{
    struct ptree_node inode_node;

    spinlock_t hierarchy_lock;
    size_t children_count;
    struct stree children_tree;

    struct fs_node fs_node;
};

struct vfs_mount
{
    spinlock_t lock;
    struct ptree inode_tree;
    size_t num_nodes;

    size_t root_inode;

    struct vfs_node root_node;

    struct fs_mount fs_mount;
};

struct vfs_mount *
vfs_mount_create(void);

int
vfs_mount_destroy(
        struct vfs_mount *mnt);

// Insert a node and assign it a random inode number
// If "inode_index_out" is non-NULL, it will be set to the allocated inode number.
int
vfs_mount_insert_node(
        struct vfs_mount *mnt,
        struct vfs_node *node,
        size_t *inode_index_out
        );

// Remove the node and deallocate it's inode number
int
vfs_mount_remove_node(
        struct vfs_mount *mnt,
        struct vfs_node *node);

int
vfs_mount_link_root(
        struct vfs_mount *mnt,
        const char *name,
        size_t inode);

int
vfs_mount_unlink_root(
        struct vfs_mount *mnt,
        const char *name);

int
vfs_node_link(
        struct vfs_node *node,
        const char *name,
        size_t inode);

int
vfs_node_unlink(
        struct vfs_node *node,
        const char *name); 

// Unlinks all children of this node
int
vfs_node_unlink_all(
        struct vfs_node *node);

int
vfs_mount_insert_node_and_link_root(
        struct vfs_mount *mnt,
        struct vfs_node *node,
        const char *name);

// fs_file_ops
int
vfs_dir_lookup(
        struct fs_node *fs_node,
        const char *name,
        size_t * inode);
int
vfs_dir_begin(
        struct file *dir);
int
vfs_dir_next(
        struct file *dir);
int
vfs_dir_readattr(
        struct file *file,
        int attr,
        size_t *value);
int
vfs_dir_readname(
        struct file *dir,
        char *name_buf,
        size_t buf_len);

// "struct" nodes

struct vfs_struct_node;

// create a struct and link it to the
// root of the vfs mount as directory "name"
struct vfs_struct_node *
vfs_create_struct_node(
        struct vfs_mount *mnt,
        const char *name);
int
vfs_destroy_struct_node(
        struct vfs_struct_node *node);

// If NULL is passed for read and/or write,
// trying to read or write the node will fail with "-EINVAL"
int
vfs_struct_node_add_unsigned_long_field(
        struct vfs_struct_node *node,
        const char *name,
        void *state,
        int(*read)(unsigned long *out, void *state),
        int(*write)(unsigned long in, void *state)
        );

// If NULL is passed for read and/or write
// trying to read or write will fail with "-EINVAL"
int
vfs_struct_node_add_buffer_field(
        struct vfs_struct_node *node,
        const char *name,
        void *state,
        ssize_t(*read)(size_t offset, char *buf_out, size_t len, void *state),
        ssize_t(*write)(size_t offset, char *buf_in, size_t len, void *state)
        );

int
vfs_struct_node_destroy_field(
        struct vfs_struct_node *node,
        const char *name);

#endif
