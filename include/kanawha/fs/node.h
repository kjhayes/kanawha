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

#define FS_NODE_READ_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(void *, page)\
ARG(uintptr_t, pfn)

#define FS_NODE_WRITE_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(void *, page)\
ARG(uintptr_t, pfn)

#define FS_NODE_FLUSH_SIG(RET,ARG)\
RET(int)

#define FS_NODE_ATTR_PAGE_ORDER 0
#define FS_NODE_ATTR_DATA_SIZE  1
#define FS_NODE_ATTR_TYPE       2

#define FS_NODE_TYPE_UNKNOWN (0)
#define FS_NODE_TYPE_FILE    (1)
#define FS_NODE_TYPE_DIR     (2)
#define FS_NODE_TYPE_FIFO    (3)
#define FS_NODE_TYPE_SPECIAL (4)

#define FS_NODE_GETATTR_SIG(RET,ARG)\
RET(int)\
ARG(int, attr)\
ARG(size_t *, value)

#define FS_NODE_SETATTR_SIG(RET,ARG)\
RET(int)\
ARG(int, attr)\
ARG(size_t, value)

#define FS_NODE_LOOKUP_SIG(RET,ARG)\
RET(int)\
ARG(const char *, name)\
ARG(size_t *, inode)

#define FS_NODE_MKFILE_SIG(RET,ARG)\
RET(int)\
ARG(const char *, filename)\
ARG(unsigned long, flags)

#define FS_NODE_MKFIFO_SIG(RET,ARG)\
RET(int)\
ARG(const char *, filename)\
ARG(unsigned long, flags)

#define FS_NODE_MKDIR_SIG(RET,ARG)\
RET(int)\
ARG(const char *, dirname)\
ARG(unsigned long, flags)

#define FS_NODE_LINK_SIG(RET,ARG)\
RET(int)\
ARG(const char *, linkname)\
ARG(size_t, inode)

#define FS_NODE_SYMLINK_SIG(RET,ARG)\
RET(int)\
ARG(const char *, linkname)\
ARG(const char *, path)

#define FS_NODE_UNLINK_SIG(RET,ARG)\
RET(int)\
ARG(const char *, name)

#define FS_NODE_OP_LIST(OP, ...)\
OP(read_page, FS_NODE_READ_PAGE_SIG, ##__VA_ARGS__)\
OP(write_page, FS_NODE_WRITE_PAGE_SIG, ##__VA_ARGS__)\
OP(flush, FS_NODE_FLUSH_SIG, ##__VA_ARGS__)\
OP(getattr, FS_NODE_GETATTR_SIG, ##__VA_ARGS__)\
OP(setattr, FS_NODE_SETATTR_SIG, ##__VA_ARGS__)\
OP(lookup, FS_NODE_LOOKUP_SIG, ##__VA_ARGS__)\
OP(mkfile, FS_NODE_MKFILE_SIG, ##__VA_ARGS__)\
OP(mkfifo, FS_NODE_MKFIFO_SIG, ##__VA_ARGS__)\
OP(mkdir, FS_NODE_MKDIR_SIG, ##__VA_ARGS__)\
OP(link, FS_NODE_LINK_SIG, ##__VA_ARGS__)\
OP(symlink, FS_NODE_SYMLINK_SIG, ##__VA_ARGS__)\
OP(unlink, FS_NODE_UNLINK_SIG, ##__VA_ARGS__)

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
    // Operate on the node directly
    struct fs_node_ops *node_ops;
    // Operate on a file descriptor/node pair
    struct fs_file_ops *file_ops;

    struct fs_mount *mount;

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
        ->node_ops->,
        SELF_ACCESSOR)

#undef FS_NODE_READ_PAGE_SIG
#undef FS_NODE_WRITE_PAGE_SIG
#undef FS_NODE_GETATTR_SIG
#undef FS_NODE_SETATTR_SIG
#undef FS_NODE_LOOKUP_SIG
#undef FS_NODE_MKFILE_SIG
#undef FS_NODE_MKDIR_SIG
#undef FS_NODE_LINK_SIG
#undef FS_NODE_SYMLINK_SIG
#undef FS_NODE_UNLINK_SIG
#undef FS_NODE_OP_LIST

int
fs_node_get(
        struct fs_node *node);
int
fs_node_put(
        struct fs_node *node);

int
fs_node_page_order(
        struct fs_node *node,
        order_t *order);

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

int
fs_node_paged_read(
        struct fs_node *node,
        uintptr_t offset,
        void *buffer,
        size_t buflen);

int
fs_node_paged_write(
        struct fs_node *node,
        uintptr_t offset,
        void *buffer,
        size_t buflen);

/*
 * Error fs_node Method Implementations
 */

int
fs_node_cannot_read_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn);
int
fs_node_cannot_write_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn);
int
fs_node_cannot_flush(
        struct fs_node *node);
int
fs_node_cannot_getattr(
        struct fs_node *node,
        int attr,
        size_t *value);
int
fs_node_cannot_setattr(
        struct fs_node *node,
        int attr,
        size_t value);
int
fs_node_cannot_lookup(
        struct fs_node *node,
        const char *name,
        size_t *inode);
int
fs_node_cannot_mkfile(
        struct fs_node *node,
        const char *name,
        unsigned long flags);
int
fs_node_cannot_mkfifo(
        struct fs_node *node,
        const char *name,
        unsigned long flags);
int
fs_node_cannot_mkdir(
        struct fs_node *node,
        const char *name,
        unsigned long flags);
int
fs_node_cannot_link(
        struct fs_node *node,
        const char *name,
        size_t inode);
int
fs_node_cannot_symlink(
        struct fs_node *node,
        const char *name,
        const char *path);
int
fs_node_cannot_unlink(
        struct fs_node *node,
        const char *name);

#endif
