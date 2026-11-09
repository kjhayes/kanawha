
#define KEEP_FS_NODE_OP_LIST

#include <kanawha/fs/node.h>

#include <kanawha/assert.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

#define fs_node_page_lock_init(__node_ptr)                                     \
    thread_lock_init(&__node_ptr->page_lock)
#define fs_node_page_lock_acquire(__node_ptr)                                  \
    thread_lock_acquire(&__node_ptr->page_lock)
#define fs_node_page_lock_release(__node_ptr)                                  \
    thread_lock_release(&__node_ptr->page_lock)

#define FS_NODE_OPS_ACCESSOR(__self, __field) __self->backing.node_ops->__field

#define FS_NODE_OP_ACQUIRE_LOCK(ptr) rlock_read_lock(&ptr->backing_lock)
#define FS_NODE_OP_RELEASE_LOCK(ptr) rlock_read_unlock(&ptr->backing_lock)

DEFINE_OP_LIST_WRAPPERS_WITH_PRE_POST(FS_NODE_OP_LIST,
                                      ,
                                      /* No Prefix */,
                                      fs_node,
                                      FS_NODE_OPS_ACCESSOR,
                                      SELF_ACCESSOR,
                                      FS_NODE_OP_ACQUIRE_LOCK,
                                      FS_NODE_OP_RELEASE_LOCK)

static int
fs_node_flush_fs_page_lockless(struct fs_node *node, struct fs_page *page)
{
    int res;

    size_t amount = page->size;

    page->flags &= ~FS_PAGE_FLAG_DIRTY;

    unsigned long pfn = pcache_node_get_index(&page->cache_node);
    res = fs_node_flush_page(node, pfn, 0, page->paddr);
    if(res)
    {
        page->flags |= FS_PAGE_FLAG_DIRTY;
        return res;
    }
    if(amount < page->size)
    {
        page->flags |= FS_PAGE_FLAG_DIRTY;
        return -EAGAIN;
    }

    return 0;
}

static int
fs_node_page_cache_load(
        struct pcache *cache,
        size_t index,
        struct pcache_node **out)
{
    int res;

    struct fs_node *node = container_of(cache, struct fs_node, page_cache);

    struct fs_page *page = NULL;

    page = kzmalloc(sizeof(struct fs_page), KM_KERNEL);
    if(page == NULL)
    {
        return -ENOMEM;
    }

    page->pins = 1;

    order_t order;
    res = fs_node_page_order(node, &order);
    if(res)
    {
        kfree(page);
        return res;
    }

    //unsigned long load_page_flags = flags & FS_NODE_GET_PAGE_MAY_CREATE
    //                                    ? FS_NODE_LOAD_PAGE_MAY_CREATE
    //                                    : 0;

    unsigned long load_page_flags = 0;

    res = fs_node_load_page(node, index, load_page_flags, &page->paddr);
    if(res)
    {
        kfree(page);
        return res;
    }

    page->order = order;
    page->size = 1ULL << order;
    page->flags = 0;

    DEBUG_ASSERT(KERNEL_ADDR(out));
    *out = &page->cache_node;

    return 0;
}

static int
fs_node_page_cache_unload(
        struct pcache *cache,
        size_t index,
        struct pcache_node *pcache_node)
{
    int res;

    struct fs_node *node = container_of(cache, struct fs_node, page_cache);
    struct fs_page *page = container_of(pcache_node, struct fs_page, cache_node);

    if(page->flags & FS_PAGE_FLAG_DIRTY)
    {
        res = fs_node_flush_fs_page_lockless(node, page);
        if(res)
        {
            eprintk("fs_node_page_cache_unload failed because "
                    "fs_node_flush_fs_page_lockless returned "
                    "(%s) with "
                    "dirty page!\n",
                    errnostr(res));
            return res;
        }
    }

    res = fs_node_unload_page(node,
                              index,
                              0, // flags
                              page->paddr);
    if(res)
    {
        eprintk("Failed to unload fs_page backing page order=%ld, "
                "phys_addr=%p! (err=%s)\n",
                (sl_t)page->order,
                page->paddr,
                errnostr(res));
    }

    kfree(page);

    return 0;
}

static int
fs_node_page_cache_flush(
        struct pcache *cache,
        size_t index,
        struct pcache_node *pcache_node)
{
    struct fs_node *node = container_of(cache, struct fs_node, page_cache);
    struct fs_page *page = container_of(pcache_node, struct fs_page, cache_node);
    return fs_node_flush_fs_page_lockless(node, page);
}

static struct pcache_ops
fs_node_page_pcache_ops = {
    .load_node = fs_node_page_cache_load,
    .unload_node = fs_node_page_cache_unload,
    .flush_node = fs_node_page_cache_flush,
};

struct fs_node *
fs_node_create(void)
{
    struct fs_node *fs_node;

    fs_node = kzmalloc(sizeof(*fs_node), KM_KERNEL);
    if(fs_node == NULL)
    {
        return NULL;
    }

    rlock_init(&fs_node->backing_lock);

    pcache_init(&fs_node->page_cache, &fs_node_page_pcache_ops);

    return fs_node;
}

int
fs_node_get(struct fs_node *node)
{
    pcache_node_get(&node->cache_node);
    return 0;
}

int
fs_node_put(struct fs_node *node)
{
    pcache_node_put(&node->cache_node);
    return 0;
}

struct fs_node_ops *
fs_node_get_node_ops(struct fs_node *node)
{
    return node->backing.node_ops;
}
struct fs_file_ops *
fs_node_get_file_ops(struct fs_node *node)
{
    return node->backing.file_ops;
}

size_t
fs_node_get_inode(struct fs_node *node)
{
    return pcache_node_get_index(&node->cache_node);
}

// FS-Node Caching

int
fs_node_page_order(struct fs_node *node, order_t *order)
{
    int res;
    size_t node_order;
    res = fs_node_getattr(node, FS_NODE_ATTR_PAGE_ORDER, &node_order);
    if(res)
    {
        return res;
    }

    *order = (order_t)node_order;

    return 0;
}

struct fs_page *
fs_node_get_page(struct fs_node *node, uintptr_t pfn, unsigned long flags)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(node));
    struct pcache_node *pcache_node = NULL;
    res = pcache_lookup_node(
            &node->page_cache,
            pfn,
            &pcache_node);
    if(res) {
        return NULL;
    }
    DEBUG_ASSERT(KERNEL_ADDR(pcache_node));
    return container_of(pcache_node, struct fs_page, cache_node);
}

int
fs_page_get(struct fs_page *page)
{
    pcache_node_get(&page->cache_node);
    return 0;
}

int
fs_page_put(struct fs_page *page)
{
    pcache_node_put(&page->cache_node);
    return 0;
}

int
fs_page_mark_dirty(
        struct fs_page *page)
{
    page->flags |= FS_PAGE_FLAG_DIRTY;
    return 0;
}

int
fs_node_flush_fs_page(struct fs_node *node, struct fs_page *page)
{
    return fs_node_flush_fs_page_lockless(node, page);
}

int
fs_node_flush_all_fs_pages(struct fs_node *node)
{
    return pcache_flush_all(&node->page_cache);
}

int
fs_node_paged_read(struct fs_node *fs_node,
                   uintptr_t offset,
                   void *buffer,
                   size_t buflen,
                   unsigned long flags)
{
    int res;

    dprintk("fs_node_paged_read\n");

    size_t original_len = buflen;
    size_t total_read = 0;

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res)
    {
        return res;
    }

    unsigned long get_page_flags =
        flags & FS_NODE_PAGED_READ_MAY_EXTEND ? FS_NODE_GET_PAGE_MAY_CREATE : 0;

    while(buflen > 0)
    {
        uintptr_t offset_pfn = offset >> order;
        uintptr_t page_offset = offset & ((1ULL << order) - 1);
        uintptr_t room_left = (1ULL << order) - page_offset;

        struct fs_page *page =
            fs_node_get_page(fs_node, offset_pfn, get_page_flags);
        if(page == NULL)
        {
            return -ENXIO;
        }

        ssize_t to_read = buflen < room_left ? buflen : room_left;

        memcpy(buffer, (void *)__va(page->paddr) + page_offset, to_read);

        buffer += to_read;
        buflen -= to_read;
        total_read += to_read;
        offset += to_read;

        fs_page_put(page);
    }

    size_t page_end = offset + buflen;

    // Attempt to increase the size of the file
    if(flags & FS_NODE_PAGED_READ_MAY_EXTEND)
    {
        size_t cur_size;
        res = fs_node_getattr(fs_node, FS_NODE_ATTR_DATA_SIZE, &cur_size);
        if(!res)
        {
            if(cur_size < page_end)
            {
                res =
                    fs_node_setattr(fs_node, FS_NODE_ATTR_DATA_SIZE, page_end);
                if(res)
                {
                    // Ignore the error, we'll only try to
                    // change the file size as a "best-effort"
                    // attempt
                    //
                    // (Special files may not allow us to)
                }
            }
        }
    }

    DEBUG_ASSERT(total_read == original_len);

    return 0;
}

int
fs_node_paged_write(struct fs_node *fs_node,
                    uintptr_t offset,
                    void *buffer,
                    size_t buflen,
                    unsigned long flags)
{
    int res;

    dprintk("fs_node_paged_write\n");

    size_t original_len = buflen;
    size_t total_read = 0;

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res)
    {
        return res;
    }

    unsigned long get_page_flags = flags & FS_NODE_PAGED_WRITE_MAY_EXTEND
                                       ? FS_NODE_GET_PAGE_MAY_CREATE
                                       : 0;

    while(buflen > 0)
    {
        uintptr_t offset_pfn = offset >> order;
        uintptr_t page_offset = offset & ((1ULL << order) - 1);
        uintptr_t room_left = (1ULL << order) - page_offset;

        struct fs_page *page =
            fs_node_get_page(fs_node, offset_pfn, get_page_flags);
        if(page == NULL)
        {
            return -EINVAL;
        }

        ssize_t to_read = buflen < room_left ? buflen : room_left;

        memcpy((void *)__va(page->paddr) + page_offset, buffer, to_read);

        buffer += to_read;
        buflen -= to_read;
        total_read += to_read;
        offset += to_read;

        fs_page_mark_dirty(page);
        fs_page_put(page);
    }

    size_t page_end = offset + buflen;

    // Attempt to increase the size of the file
    if(flags & FS_NODE_PAGED_WRITE_MAY_EXTEND)
    {
        size_t cur_size;
        res = fs_node_getattr(fs_node, FS_NODE_ATTR_DATA_SIZE, &cur_size);
        if(!res)
        {
            if(cur_size < page_end)
            {
                res =
                    fs_node_setattr(fs_node, FS_NODE_ATTR_DATA_SIZE, page_end);
                if(res)
                {
                    // Ignore the error, we'll only try to
                    // change the file size as a "best-effort"
                    // attempt
                    //
                    // (Special files may not allow us to)
                }
            }
        }
    }

    DEBUG_ASSERT(total_read == original_len);

    return 0;
}

/*
 * Deattached fs_node Methods
 */

int
fs_node_deattached_read_page(struct fs_node *node,
                             void *page,
                             uintptr_t pfn,
                             unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_write_page(struct fs_node *node,
                              void *page,
                              uintptr_t pfn,
                              unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_load_page(struct fs_node *node,
                             uintptr_t pfn,
                             unsigned long flags,
                             void __phys **addr_out)
{
    return -ENODEV;
}
int
fs_node_deattached_unload_page(struct fs_node *node,
                               uintptr_t pfn,
                               unsigned long flags,
                               void __phys *addr)
{
    return -ENODEV;
}
int
fs_node_deattached_flush_page(struct fs_node *node,
                              uintptr_t pfn,
                              unsigned long flags,
                              void __phys *addr)
{
    return -ENODEV;
}
int
fs_node_deattached_flush(struct fs_node *node, unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_getattr(struct fs_node *node, int attr, size_t *value)
{
    return -ENODEV;
}
int
fs_node_deattached_setattr(struct fs_node *node, int attr, size_t value)
{
    return -ENODEV;
}
int
fs_node_deattached_lookup(struct fs_node *node,
                          const char *name,
                          size_t *inode,
                          char *sym_buffer,
                          size_t sym_link)
{
    return -ENODEV;
}
int
fs_node_deattached_mkfile(struct fs_node *node,
                          const char *name,
                          unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_mkfifo(struct fs_node *node,
                          const char *name,
                          unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_mkdir(struct fs_node *node,
                         const char *name,
                         unsigned long flags)
{
    return -ENODEV;
}
int
fs_node_deattached_link(struct fs_node *node, const char *name, size_t inode)
{
    return -ENODEV;
}
int
fs_node_deattached_symlink(struct fs_node *node,
                           const char *name,
                           const char *path)
{
    return -ENODEV;
}
int
fs_node_deattached_unlink(struct fs_node *node, const char *name)
{
    return -ENODEV;
}

ssize_t
fs_file_deattached_read(struct file *file,
                        void *buf,
                        ssize_t buflen,
                        unsigned long flags)
{
    return -ENODEV;
}
ssize_t
fs_file_deattached_write(struct file *file,
                         void *buf,
                         ssize_t buflen,
                         unsigned long flags)
{
    return -ENODEV;
}
ssize_t
fs_file_deattached_seek(struct file *file, ssize_t offset, int whence)
{
    return -ENODEV;
}
int
fs_file_deattached_flush(struct file *file, unsigned long flags)
{
    return -ENODEV;
}
int
fs_file_deattached_dir_begin(struct file *file)
{
    return -ENODEV;
}
int
fs_file_deattached_dir_next(struct file *file)
{
    return -ENODEV;
}
int
fs_file_deattached_dir_readattr(struct file *file, int attr, size_t *value)
{
    return -ENODEV;
}
int
fs_file_deattached_dir_readname(struct file *file, char *buf, size_t buflen)
{
    return -ENODEV;
}
int
fs_file_deattached_poll(struct file *file,
                        unsigned long watching,
                        unsigned long *triggered)
{
    return -ENODEV;
}

static struct fs_node_ops fs_node_deattached_node_ops = {
    .read_page = fs_node_deattached_read_page,
    .write_page = fs_node_deattached_write_page,
    .load_page = fs_node_deattached_load_page,
    .unload_page = fs_node_deattached_unload_page,
    .flush_page = fs_node_deattached_flush_page,
    .flush = fs_node_deattached_flush,
    .getattr = fs_node_deattached_getattr,
    .setattr = fs_node_deattached_setattr,
    .lookup = fs_node_deattached_lookup,
    .mkfile = fs_node_deattached_mkfile,
    .mkfifo = fs_node_deattached_mkfifo,
    .mkdir = fs_node_deattached_mkdir,
    .link = fs_node_deattached_link,
    .symlink = fs_node_deattached_symlink,
    .unlink = fs_node_deattached_unlink,
};
FS_NODE_OPS_INIT_UNDEF(fs_node_deattached_node_ops);

static struct fs_file_ops fs_node_deattached_file_ops = {
    .read = fs_file_deattached_read,
    .write = fs_file_deattached_write,
    .seek = fs_file_deattached_seek,
    .flush = fs_file_deattached_flush,
    .dir_begin = fs_file_deattached_dir_begin,
    .dir_next = fs_file_deattached_dir_next,
    .dir_readattr = fs_file_deattached_dir_readattr,
    .dir_readname = fs_file_deattached_dir_readname,
    .on_open = fs_file_nop_on_open,
    .on_close = fs_file_nop_on_close,
};
FS_FILE_OPS_INIT_UNDEF(fs_node_deattached_file_ops);

int
fs_node_deattach_backing(struct fs_node *node)
{
    rlock_write_lock(&node->backing_lock);
    node->backing.node_ops = &fs_node_deattached_node_ops;
    node->backing.file_ops = &fs_node_deattached_file_ops;
    node->backing.priv_state = NULL;
    // We are still associated with the mount (TODO)
    rlock_write_unlock(&node->backing_lock);
    return 0;
}

/*
 * Error fs_node Method Implementations
 */

int
fs_node_cannot_read_page(struct fs_node *node,
                         void *page,
                         uintptr_t pfn,
                         unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_write_page(struct fs_node *node,
                          void *page,
                          uintptr_t pfn,
                          unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_load_page(struct fs_node *node,
                         uintptr_t pfn,
                         unsigned long flags,
                         void __phys **addr_out)
{
    return -EINVAL;
}
int
fs_node_cannot_unload_page(struct fs_node *node,
                           uintptr_t pfn,
                           unsigned long flags,
                           void __phys *addr)
{
    return -EINVAL;
}
int
fs_node_cannot_flush_page(struct fs_node *node,
                          uintptr_t pfn,
                          unsigned long flags,
                          void __phys *addr)
{
    return -EINVAL;
}
int
fs_node_cannot_flush(struct fs_node *node, unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_getattr(struct fs_node *node, int attr, size_t *value)
{
    return -EINVAL;
}
int
fs_node_cannot_setattr(struct fs_node *node, int attr, size_t value)
{
    return -EINVAL;
}
int
fs_node_cannot_lookup(struct fs_node *node,
                      const char *name,
                      size_t *inode,
                      char *sym_buffer,
                      size_t sym_link)
{
    return -EINVAL;
}
int
fs_node_cannot_mkfile(struct fs_node *node,
                      const char *name,
                      unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_mkfifo(struct fs_node *node,
                      const char *name,
                      unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_mkdir(struct fs_node *node,
                     const char *name,
                     unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_link(struct fs_node *node, const char *name, size_t inode)
{
    return -EINVAL;
}
int
fs_node_cannot_symlink(struct fs_node *node, const char *name, const char *path)
{
    return -EINVAL;
}
int
fs_node_cannot_unlink(struct fs_node *node, const char *name)
{
    return -EINVAL;
}

int
fs_node_cannot_connect(struct fs_node *node, size_t *inode, unsigned long flags)
{
    return -EINVAL;
}

int
fs_node_cannot_accept(struct fs_node *node, size_t *inode, unsigned long flags)
{
    return -EINVAL;
}

int
fs_node_load_page_read_alloc(struct fs_node *node,
                             uintptr_t pfn,
                             unsigned long flags,
                             void __phys **addr_out)
{
    int res;

    order_t order;
    res = fs_node_page_order(node, &order);
    if(res)
    {
        return res;
    }

    void __phys *addr;

    res = page_alloc(order, &addr, 0);
    if(res)
    {
        return res;
    }

    unsigned long read_page_flags =
        flags & FS_NODE_LOAD_PAGE_MAY_CREATE ? FS_NODE_READ_PAGE_MAY_CREATE : 0;

    res = fs_node_read_page(node, (void *)__va(addr), pfn, read_page_flags);
    if(res)
    {
        page_free(order, addr);
        return res;
    }

    *addr_out = addr;
    return 0;
}
int
fs_node_unload_page_free(struct fs_node *node,
                         uintptr_t pfn,
                         unsigned long flags,
                         void __phys *addr)
{
    int res;

    order_t order;
    res = fs_node_page_order(node, &order);
    if(res)
    {
        return res;
    }

    res = page_free(order, addr);
    if(res)
    {
        return res;
    }

    return 0;
}

int
fs_node_flush_page_write(struct fs_node *node,
                         uintptr_t pfn,
                         unsigned long flags,
                         void __phys *addr)
{
    int res;

    unsigned long write_page_flags = FS_NODE_WRITE_PAGE_MAY_CREATE;

    res = fs_node_write_page(node, (void *)__va(addr), pfn, write_page_flags);
    if(res)
    {
        return res;
    }

    return 0;
}

int
fs_node_flush_nop(struct fs_node *node, unsigned long flags)
{
    return 0;
}
int
fs_node_flush_page_nop(struct fs_node *node,
                       uintptr_t pfn,
                       unsigned long flags,
                       void __phys *addr)
{
    return 0;
}
