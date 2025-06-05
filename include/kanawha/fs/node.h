
#ifdef KEEP_FS_NODE_STRUCT_DEF
#ifndef __KANAWHA__FS_NODE_STRUCT_DEF__
#define __KANAWHA__FS_NODE_STRUCT_DEF__
#include <kanawha/ops.h>
#include <kanawha/types.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/lock.h>

struct fs_type;
struct fs_mount;
struct fs_node;

struct fs_node
{
    // Operate on the node directly
    struct fs_node_ops *node_ops;
    // Operate on a file descriptor/node pair
    struct fs_file_ops *file_ops;

    // Unload this node, including freeing this struct
    // (If NULL, fs_mount_unload_node will be used instead,
    //  if non-NULL, fs_mount_unload_node will not be invoked)
    int(*unload)(struct fs_node *node);

    struct fs_mount *mount;

    spinlock_t page_lock;
    struct ptree page_cache;

    irq_lock_t path_lock;
    ilist_t path_list;

    // not a refcount_t because the mount cache_lock protects us
    int refcount;
    struct ptree_node cache_node;
};

static inline void
fs_node_path_lock_acquire(
        struct fs_node *node)
{
    irq_lock_acquire(&node->path_lock);
}
static inline void
fs_node_path_lock_release(
        struct fs_node *node)
{
    irq_lock_release(&node->path_lock);
}

#endif
#endif

#ifndef __KANAWHA__FS_NODE_H__
#define __KANAWHA__FS_NODE_H__

#include <kanawha/ops.h>
#include <kanawha/types.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/lock.h>

struct fs_type;
struct fs_mount;
struct fs_node;


#define FS_NODE_READ_PAGE_MAY_CREATE (1ULL<<0)

#define FS_NODE_READ_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(void *, page)\
ARG(uintptr_t, pfn)\
ARG(unsigned long, flags)

#define FS_NODE_WRITE_PAGE_MAY_CREATE (1ULL<<0)

#define FS_NODE_WRITE_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(void *, page)\
ARG(uintptr_t, pfn)\
ARG(unsigned long, flags)

/*
 * Load/Unloading implementations do not need to keep track of reference counts
 *
 * That should be managed at the "fs_page" level, and so "load" should
 * only be called once before unloading, and vice-versa.
 */

#define FS_NODE_LOAD_PAGE_MAY_CREATE (1ULL<<0)

#define FS_NODE_LOAD_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(uintptr_t, pfn)\
ARG(unsigned long, flags)\
ARG(void __phys **, addr_out)

#define FS_NODE_UNLOAD_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(uintptr_t, pfn)\
ARG(unsigned long, flags)\
ARG(void __phys *, addr)

#define FS_NODE_FLUSH_PAGE_SIG(RET,ARG)\
RET(int)\
ARG(uintptr_t, pfn)\
ARG(unsigned long, flags)\
ARG(void __phys *, addr)

// Flush any node meta-data/directory info
#define FS_NODE_FLUSH_SIG(RET,ARG)\
RET(int)\
ARG(unsigned long, flags)

#define FS_NODE_ATTR_PAGE_ORDER 0
#define FS_NODE_ATTR_DATA_SIZE  1
#define FS_NODE_ATTR_TYPES      2

#define FS_NODE_TYPE_REGULAR   (1ULL<<0)
#define FS_NODE_TYPE_DIRECTORY (1ULL<<1)
#define FS_NODE_TYPE_FIFO      (1ULL<<2)

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
OP(load_page, FS_NODE_LOAD_PAGE_SIG, ##__VA_ARGS__)\
OP(unload_page, FS_NODE_UNLOAD_PAGE_SIG, ##__VA_ARGS__)\
OP(flush_page, FS_NODE_FLUSH_PAGE_SIG, ##__VA_ARGS__)\
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

    void __phys * paddr;
    order_t order;
    size_t size;

    unsigned long flags;
    struct ptree_node tree_node;
};

struct fs_node;

DECLARE_OP_LIST_WRAPPERS(
        FS_NODE_OP_LIST,
        /* No Qualifiers */,
        /* No Prefix */,
        fs_node)

#ifndef KEEP_FS_NODE_OP_LIST
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
#endif

int
fs_node_get(
        struct fs_node *node);
int
fs_node_put(
        struct fs_node *node);

struct fs_node_ops *
fs_node_get_node_ops(
        struct fs_node *node);
struct fs_file_ops *
fs_node_get_file_ops(
        struct fs_node *node);

size_t
fs_node_get_inode(
        struct fs_node *node);

int
fs_node_page_order(
        struct fs_node *node,
        order_t *order);

#define FS_NODE_GET_PAGE_MAY_CREATE (1ULL<<0)
struct fs_page *
fs_node_get_page(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags);

int
fs_node_put_page(
        struct fs_node *node,
        struct fs_page *page,
        int modified);

int
fs_page_get(
        struct fs_node *node,
        struct fs_page *page);

int
fs_node_flush_fs_page(
        struct fs_node *node,
        struct fs_page *page);

int
fs_node_flush_all_fs_pages(
        struct fs_node *node);

#define FS_NODE_PAGED_READ_MAY_EXTEND (1ULL<<0)
int
fs_node_paged_read(
        struct fs_node *node,
        uintptr_t offset,
        void *buffer,
        size_t buflen,
        unsigned long flags);

#define FS_NODE_PAGED_WRITE_MAY_EXTEND (1ULL<<0)
int
fs_node_paged_write(
        struct fs_node *node,
        uintptr_t offset,
        void *buffer,
        size_t buflen,
        unsigned long flags);

/*
 * Error fs_node Method Implementations
 */

int
fs_node_cannot_read_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn,
        unsigned long flags);
int
fs_node_cannot_write_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn,
        unsigned long flags);
int
fs_node_cannot_load_page(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys ** addr_out);
int
fs_node_cannot_unload_page(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr);
int
fs_node_cannot_flush_page(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr);
int
fs_node_cannot_flush(
        struct fs_node *node,
        unsigned long flags);
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

/*
 * Default Implementations
 */

// Load/Unload Page by allocating/freeing memory
// and calling fs_node_read/write_page
int
fs_node_load_page_read_alloc(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys ** addr);
int
fs_node_unload_page_free(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr);
int
fs_node_flush_page_write(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys * addr);
int
fs_node_flush_nop(
        struct fs_node *node,
        unsigned long flags);

#endif
