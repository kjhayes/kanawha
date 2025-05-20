#ifndef __KANAWHA__FS_PATH_H__
#define __KANAWHA__FS_PATH_H__

#include <kanawha/list.h>
#include <kanawha/proc/process.h>
#include <kanawha/spinlock.h>
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>

struct fs_mount;

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
#define FS_PATH_CHECKSUM ((uint32_t)0x8319BB15UL)
#define DEBUG_ASSERT_FS_PATH_VALID(__path_ptr)\
    do {\
    DEBUG_ASSERT(KERNEL_ADDR(__path_ptr));\
    DEBUG_ASSERT(__path_ptr->__checksum == FS_PATH_CHECKSUM);\
    } while(0)
#else
#define DEBUG_ASSERT_FS_PATH_VALID(__path_ptr)
#endif

struct fs_path
{
    char *name;

    struct fs_node *fs_node;

    unsigned long refs;

    enum {
        FS_PATH_NODE,
        FS_PATH_MOUNT,
    } type;

    unsigned long flags;

    struct fs_path *parent;
    ilist_t children;
    ilist_node_t child_node;

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    uint32_t __checksum;
#endif
};

int
fs_path_get(struct fs_path *path);

int
fs_path_put(struct fs_path *path);

// Returns an anonymous pipe with no references
int
fs_path_create_anon_pipe(
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
    if(path->fs_node == NULL) {
        return -ENXIO;
    }
    *index_out = path->fs_node->cache_node.key;
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
    if(path->fs_node == NULL) {
        return -ENXIO;
    }
    return fs_node_getattr(path->fs_node, attr, value_out);
}

int
dump_fs_paths(
        printk_f *printer);

#endif
