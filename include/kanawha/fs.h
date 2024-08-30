#ifndef __KANAWHA__FS_H__
#define __KANAWHA__FS_H__

#include <kanawha/ops.h>
#include <kanawha/stdint.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>

struct fs_type;
struct fs_mount;
struct fs_node;

/*
 * Directory Functions
 */
// If this is a directory, returns the number of sub-files
// else, returns 0
#define FS_NODE_NUM_CHILDREN_SIG(RET,ARG)\
RET(size_t)

// Get the fs_node of the child at index
// Returns NULL if no such child exists
#define FS_NODE_GET_CHILD_SIG(RET,ARG)\
RET(int)\
ARG(size_t, child_index)\
ARG(size_t*, node_index)

// Get the file-name of a specific child node
// Returns 0 on success, follows the same semantics
// as strncpy() into buffer with n=buf_size
#define FS_NODE_CHILD_NAME_SIG(RET,ARG)\
RET(int)\
ARG(size_t, index)\
ARG(char *, buf)\
ARG(size_t, buf_size)

// Get file access attribute(s)
// Returns 0 on success, negative errno on error
// (could be permissions, attribute doesn't exist, etc.)
#define FS_NODE_ATTR_MAX_OFFSET      0
#define FS_NODE_ATTR_MAX_OFFSET_END  1
#define FS_NODE_ATTR_CHILD_COUNT     2
#define FS_NODE_ATTR_SIG(RET,ARG)\
RET(int)\
ARG(int, attr_index)\
ARG(size_t *, attr_val)

// Reads *amount bytes into buffer, modifies *amount
// if less data was read than requested to be the number
// of bytes actually read.
#define FS_NODE_READ_SIG(RET,ARG)\
RET(int)\
ARG(void *, buffer)\
ARG(size_t *, amount)\
ARG(size_t, offset)

// Same as FS_NODE_READ but writes from the buffer into the
// file instead of reading
#define FS_NODE_WRITE_SIG(RET,ARG)\
RET(int)\
ARG(void *, buffer)\
ARG(size_t *, amount)\
ARG(size_t, offset)

#define FS_NODE_FLUSH_SIG(RET,ARG)\
RET(int)

#define FS_NODE_OP_LIST(OP, ...)\
OP(get_child, FS_NODE_GET_CHILD_SIG, ##__VA_ARGS__)\
OP(child_name, FS_NODE_CHILD_NAME_SIG, ##__VA_ARGS__)\
OP(attr, FS_NODE_ATTR_SIG, ##__VA_ARGS__)\
OP(read, FS_NODE_READ_SIG, ##__VA_ARGS__)\
OP(write, FS_NODE_WRITE_SIG, ##__VA_ARGS__)\
OP(flush, FS_NODE_FLUSH_SIG, ##__VA_ARGS__)

struct fs_node_ops {
DECLARE_OP_LIST_PTRS(FS_NODE_OP_LIST, struct fs_node *)
};

#define FS_PAGE_FLAG_DIRTY (1ULL<<0)
struct fs_page
{
    size_t pins;

    paddr_t paddr;
    order_t order;
    size_t size;

    unsigned long flags;
    struct ptree_node tree_node;
};

struct fs_node
{
    struct fs_node_ops *ops;

    struct fs_mount *mount;

    void *mnt_state;

    spinlock_t page_lock;
    struct ptree page_cache;

    // not a refcount_t because the mount cache_lock protects us
    int refcount;
    struct ptree_node cache_node;
};

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

#define FS_TYPE_MOUNT_FILE_SIG(RET,ARG)\
RET(int)\
ARG(struct fs_node *, node)\
ARG(struct fs_mount **, out_mnt)\

#define FS_TYPE_UNMOUNT_SIG(RET,ARG)\
RET(int)\
ARG(struct fs_mount *, mnt)

#define FS_TYPE_OP_LIST(OP, ...)\
OP(mount_file, FS_TYPE_MOUNT_FILE_SIG, ##__VA_ARGS__)\
OP(unmount, FS_TYPE_UNMOUNT_SIG, ##__VA_ARGS__)

struct fs_type {
DECLARE_OP_LIST_PTRS(FS_TYPE_OP_LIST, struct fs_type *)
    struct stree_node fs_type_node;
};

DEFINE_OP_LIST_WRAPPERS(
        FS_NODE_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_node,
        ->ops->,
        SELF_ACCESSOR)

DEFINE_OP_LIST_WRAPPERS(
        FS_MOUNT_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_mount,
        ->ops->,
        SELF_ACCESSOR)

DEFINE_OP_LIST_WRAPPERS(
        FS_TYPE_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_type,
        ->,
        SELF_ACCESSOR)

// Keeps a reference to name
int register_fs_type(
        struct fs_type *type,
        char *name);

// Initialize generic fields of an fs_mount,
// for use by implementations of fs_type_mount_*
int init_fs_mount_struct(
        struct fs_mount *mnt,
        struct fs_mount_ops *ops);

struct fs_type *
fs_type_find(const char *name);

// Keeps a reference to "name"
int
fs_attach_mount(
        struct fs_mount *mount,
        const char *name);

struct fs_mount *
fs_deattach_mount(
        const char *name);

struct fs_mount *
fs_mount_lookup(const char *name);

int
fs_path_lookup(
        const char *path,
        struct fs_mount **mnt,
        struct fs_node **node);

int
fs_node_lookup(
        struct fs_mount *mnt,
        const char *path,
        size_t *index_out);

struct fs_node *
fs_mount_get_node(
        struct fs_mount *mnt,
        size_t node_index);

int
fs_mount_put_node(
        struct fs_mount *mnt,
        struct fs_node *node);

order_t
fs_node_page_order(
        struct fs_node *node);

struct fs_page *
fs_node_get_page(
        struct fs_node *node,
        uintptr_t pfn);

int
fs_node_put_page(
        struct fs_node *node,
        struct fs_page *page,
        int modified);

int
fs_node_flush_page(
        struct fs_node *node,
        struct fs_page *page);

int
fs_node_flush_all_pages(
        struct fs_node *node);

/*
 * Default fs_node Method Implementations
 */

int
childless_fs_node_get_child(struct fs_node *, size_t, size_t *);
int
childless_fs_node_child_name(struct fs_node *, size_t, char *, size_t);

int
unreadable_fs_node_read(struct fs_node *, void *, size_t *, uintptr_t);
int
immutable_fs_node_write(struct fs_node *, void *, size_t *, uintptr_t);
int
writethrough_fs_node_flush(struct fs_node *node);

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

void
fs_dump_attached_mounts(printk_f *printer, int depth);

#endif
