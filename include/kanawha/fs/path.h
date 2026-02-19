#ifndef __KANAWHA__FS_PATH_H__
#define __KANAWHA__FS_PATH_H__

#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>

struct process;
struct fs_mount;
struct fs_path;

int
fs_path_get(struct fs_path *path);

int
fs_path_put(struct fs_path *path);

struct fs_node *
fs_path_get_fs_node(struct fs_path *node);

const char *
fs_path_get_name(struct fs_path *path);

struct fs_path *
fs_path_get_parent(
        struct fs_path *path);

// Returns an anonymous pipe with no references
int
fs_path_create_anon_pipe(
        struct fs_path **out);

// Create an anonymous path to an fs_node
// (Has a single reference)
int
fs_path_create_anonymous(
        struct fs_node *node,
        struct fs_path **out);

// Returns a root mount point with a single reference
int
fs_path_mount_root(
        struct fs_mount *mnt,
        struct fs_path **out);

// Returns a child mount point with a single reference
int
fs_path_mount_dir(
        struct fs_path *parent,
        const char *name,
        struct fs_mount *mnt,
        struct fs_path **out);

int
fs_path_unmount(
        struct fs_path *mnt_point);

int
fs_path_lookup_for_process(
        struct process *process,
	    struct fs_path *dir_path,
        const char *path_str,
        unsigned long access_flags,
        unsigned long mode_flags,
        struct fs_path **out);

static inline int
fs_path_get_inode_index(
        struct fs_path *path,
        size_t *index_out)
{
    if(path == NULL) {
        return -EINVAL;
    }
    struct fs_node *node = fs_path_get_fs_node(path);
    if(node == NULL) {
        return -ENXIO;
    }
    *index_out = fs_node_get_inode(node);
    return 0;
}

static inline int
fs_path_get_inode_attr(
        struct fs_path *path,
        int attr,
        size_t *value_out)
{
    if(path == NULL) {
        return -EINVAL;
    }
    struct fs_node *node = fs_path_get_fs_node(path);
    if(node == NULL) {
        return -ENXIO;
    }
    return fs_node_getattr(node, attr, value_out);
}

int
dump_fs_paths(
        printk_f *printer);

#endif
