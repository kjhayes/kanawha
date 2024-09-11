#ifndef __KANAWHA__FS_MOUNT_H__
#define __KANAWHA__FS_MOUNT_H__

#include <kanawha/ops.h>
#include <kanawha/stdint.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>

struct fs_type;
struct fs_mount;
struct fs_node;

// Get the root fs_node of the mount
#define FS_MOUNT_ROOT_INDEX_SIG(RET,ARG)\
RET(int)\
ARG(size_t*, root_node_index)

// Populate RAM-based data structures for the fs_node
#define FS_MOUNT_LOAD_NODE_SIG(RET,ARG)\
RET(struct fs_node *)\
ARG(size_t, node_index)

#define FS_MOUNT_UNLOAD_NODE_SIG(RET,ARG)\
RET(int)\
ARG(struct fs_node *, node)

#define FS_MOUNT_OP_LIST(OP, ...)\
OP(root_index, FS_MOUNT_ROOT_INDEX_SIG, ##__VA_ARGS__)\
OP(load_node, FS_MOUNT_LOAD_NODE_SIG, ##__VA_ARGS__)\
OP(unload_node, FS_MOUNT_UNLOAD_NODE_SIG, ##__VA_ARGS__)

struct fs_mount_ops {
DECLARE_OP_LIST_PTRS(FS_MOUNT_OP_LIST, struct fs_mount *)
};

struct fs_mount
{
    struct fs_mount_ops *ops;

    struct stree_node attach_node;
    atomic_bool_t is_attached;

    spinlock_t cache_lock;
    struct ptree node_cache;
};

struct fs_node *
fs_mount_get_node(
        struct fs_mount *mnt,
        size_t node_index);

int
fs_mount_put_node(
        struct fs_mount *mnt,
        struct fs_node *node);

DEFINE_OP_LIST_WRAPPERS(
        FS_MOUNT_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_mount,
        ->ops->,
        SELF_ACCESSOR)

#undef FS_MOUNT_ROOT_INDEX_SIG
#undef FS_MOUNT_LOAD_NODE_SIG
#undef FS_MOUNT_UNLOAD_NODE_SIG
#undef FS_MOUNT_OP_LIST

// Initialize generic fields of an fs_mount,
// for use by implementations of fs_type_mount_*
int init_fs_mount_struct(
        struct fs_mount *mnt,
        struct fs_mount_ops *ops);

#endif
