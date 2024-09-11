#ifndef __KANAWHA__FS_NODE_H__
#define __KANAWHA__FS_NODE_H__

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
#define FS_NODE_ATTR_END_OFFSET FS_NODE_ATTR_MAX_OFFSET_END
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

DEFINE_OP_LIST_WRAPPERS(
        FS_NODE_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_node,
        ->ops->,
        SELF_ACCESSOR)

#undef FS_NODE_READ_SIG
#undef FS_NODE_WRITE_SIG
#undef FS_NODE_ATTR_SIG
#undef FS_NODE_FLUSH_SIG
#undef FS_NODE_CHILD_NAME_SIG
#undef FS_NODE_GET_CHILD_SIG
#undef FS_NODE_OP_LIST

int
fs_node_get(
        struct fs_node *node);
int
fs_node_put(
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

#endif
