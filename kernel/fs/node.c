
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/assert.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

int
fs_node_get(struct fs_node *node)
{
    DEBUG_ASSERT(KERNEL_ADDR(node));
    DEBUG_ASSERT(KERNEL_ADDR(node->mount));

    dprintk("fs_node_get: inode = %p\n",
            node->cache_node.key);

    struct fs_node *again
        = fs_mount_get_node(node->mount, node->cache_node.key);
    DEBUG_ASSERT(again == node);
    return 0;
}

int
fs_node_put(struct fs_node *node)
{
    return fs_mount_put_node(node->mount, node);
}

// FS-Node Caching

int
fs_node_page_order(
        struct fs_node *node,
        order_t *order)
{
    int res;
    size_t node_order;
    res = fs_node_getattr(
            node,
            FS_NODE_ATTR_PAGE_ORDER,
            &node_order);
    if(res) {
        return res;
    }

    *order = (order_t)node_order;

    return 0;
}

struct fs_page *
fs_node_get_page(
        struct fs_node *node,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    DEBUG_ASSERT(node);

    struct fs_page *page;
    spin_lock(&node->page_lock);

    struct ptree_node *pnode;
    pnode = ptree_get(&node->page_cache, pfn);
    if(pnode == NULL) {

        page = kmalloc(sizeof(struct fs_page));
        if(page == NULL) {
            spin_unlock(&node->page_lock);
            return NULL;
        }
        memset(page, 0, sizeof(struct fs_page));

        page->pins = 1;

        order_t order;
        res = fs_node_page_order(node, &order);
        if(res) {
            spin_unlock(&node->page_lock);
            return NULL;
        }

        res = page_alloc(order, &page->paddr, 0);
        if(res) {
            spin_unlock(&node->page_lock);
            kfree(page);
            return NULL;
        }

        unsigned long read_page_flags =
            flags & FS_NODE_GET_PAGE_MAY_CREATE ? FS_NODE_READ_PAGE_MAY_CREATE : 0;

        res = fs_node_read_page(
                node,
                (void*)__va(page->paddr),
                pfn,
                read_page_flags);

        if(res) {
            spin_unlock(&node->page_lock);
            page_free(order, page->paddr);
            kfree(page);
            return NULL;
        }

        page->order = order;
        page->size = 1ULL<<order;
        page->flags = 0;

        ptree_insert(&node->page_cache, &page->tree_node, pfn);

    } else {
        page = container_of(pnode, struct fs_page, tree_node);
    }

    spin_unlock(&node->page_lock);
    return page;
}

static int
fs_node_flush_page_lockless(
        struct fs_node *node,
        struct fs_page *page)
{
    int res;

    size_t amount = page->size;

    res = fs_node_write_page(
            node,
            (void*)__va(page->paddr),
            page->tree_node.key,
            FS_NODE_WRITE_PAGE_MAY_CREATE);
    if(res) {
        return res;
    }

    if(amount < page->size) {
        return -EAGAIN;
    }

    return 0;
}

int
fs_node_put_page(
        struct fs_node *node,
        struct fs_page *page,
        int modified)
{
    int res;

    dprintk("fs_node_put_page(node=%p, page=%p)\n",
            node, page);

    spin_lock(&node->page_lock);

    uintptr_t pfn = page->tree_node.key;

    if(modified) {
        page->flags |= FS_PAGE_FLAG_DIRTY;
    }

    DEBUG_ASSERT(page->pins);

    page->pins--;
    if(page->pins == 0) {
        dprintk("freeing fs_page\n");
        if(page->flags & FS_PAGE_FLAG_DIRTY) {
            res = fs_node_flush_page_lockless(
                    node,
                    page);
            if(res) {
                eprintk("fs_node_put_page failed because fs_node_flush_page_lockless returned (%s) with dirty page!\n",
                        errnostr(res));
                page->pins++;
                spin_unlock(&node->page_lock);
                return res;
            }
        }
        dprintk("fs_page flushed\n");

        struct ptree_node *rem = ptree_remove(&node->page_cache, pfn);
        DEBUG_ASSERT(rem == &page->tree_node);

        dprintk("removed ptree node\n");

        dprintk("page_free(%ld, %p)\n",
                (sl_t)page->order, page->paddr);
        res = page_free(page->order, page->paddr);
        if(res) {
            eprintk("Failed to free fs_page backing page order=%ld, phys_addr=%p! (err=%s)\n",
                    (sl_t)page->order, page->paddr, errnostr(res));
        }
        dprintk("freed phys page\n");

        kfree(page);
        dprintk("freed fs_page\n");
    }

    spin_unlock(&node->page_lock);
    return 0;
}

int
fs_node_flush_page(
        struct fs_node *node,
        struct fs_page *page)
{
    int res;
    spin_lock(&node->page_lock);
    res = fs_node_flush_page_lockless(node, page);
    spin_unlock(&node->page_lock);
    return res;
}

int
fs_node_flush_all_pages(
        struct fs_node *node)
{
    int res = 0;
    spin_lock(&node->page_lock);

    struct ptree_node *pnode = ptree_get_first(&node->page_cache);
    while(pnode != NULL) {
        struct fs_page *page =
            container_of(pnode, struct fs_page, tree_node);
        res = fs_node_flush_page_lockless(node, page);
        if(res) {
            break;
        }
        pnode = ptree_get_next(pnode);
    }

    spin_unlock(&node->page_lock);
    return res;
}

int
fs_node_paged_read(
        struct fs_node *fs_node,
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
    if(res) {
        return res;
    }

    unsigned long get_page_flags =
        flags & FS_NODE_PAGED_READ_MAY_EXTEND ? FS_NODE_GET_PAGE_MAY_CREATE : 0;

    while(buflen > 0)
    {
        uintptr_t offset_pfn = offset >> order;
        uintptr_t page_offset = offset & ((1ULL<<order)-1);
        uintptr_t room_left = (1ULL<<order) - page_offset;

        struct fs_page *page = fs_node_get_page(fs_node, offset_pfn, get_page_flags);
        if(page == NULL) {
            return -ENXIO;
        }

        ssize_t to_read = buflen < room_left ? buflen : room_left;

        memcpy(buffer, (void*)__va(page->paddr) + page_offset, to_read);

        buffer += to_read;
        buflen -= to_read;
        total_read += to_read;
        offset += to_read;

        fs_node_put_page(fs_node, page, 0);
    }

    size_t page_end = offset + buflen;

    // Attempt to increase the size of the file
    if(flags & FS_NODE_PAGED_READ_MAY_EXTEND) {
        size_t cur_size;
        res = fs_node_getattr(
                fs_node,
                FS_NODE_ATTR_DATA_SIZE,
                &cur_size);
        if(!res) {
            if(cur_size < page_end) {
                res = fs_node_setattr(
                        fs_node,
                        FS_NODE_ATTR_DATA_SIZE,
                        page_end);
                if(res) {
                    // Ignore the error, we'll only try to change the file size
                    // as a "best-effort" attempt
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
fs_node_paged_write(
        struct fs_node *fs_node,
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
    if(res) {
        return res;
    }

    unsigned long get_page_flags =
        flags & FS_NODE_PAGED_WRITE_MAY_EXTEND ? FS_NODE_GET_PAGE_MAY_CREATE : 0;

    while(buflen > 0)
    {
        uintptr_t offset_pfn = offset >> order;
        uintptr_t page_offset = offset & ((1ULL<<order)-1);
        uintptr_t room_left = (1ULL<<order) - page_offset;

        struct fs_page *page = fs_node_get_page(fs_node, offset_pfn, get_page_flags);
        if(page == NULL) {
            return -EINVAL;
        }

        ssize_t to_read = buflen < room_left ? buflen : room_left;

        memcpy((void*)__va(page->paddr) + page_offset, buffer, to_read);

        buffer += to_read;
        buflen -= to_read;
        total_read += to_read;
        offset += to_read;

        fs_node_put_page(fs_node, page, 1);
    }

    size_t page_end = offset + buflen;

    // Attempt to increase the size of the file
    if(flags & FS_NODE_PAGED_WRITE_MAY_EXTEND) {
        size_t cur_size;
        res = fs_node_getattr(
                fs_node,
                FS_NODE_ATTR_DATA_SIZE,
                &cur_size);
        if(!res) {
            if(cur_size < page_end) {
                res = fs_node_setattr(
                        fs_node,
                        FS_NODE_ATTR_DATA_SIZE,
                        page_end);
                if(res) {
                    // Ignore the error, we'll only try to change the file size
                    // as a "best-effort" attempt
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
 * Error fs_node Method Implementations
 */

int
fs_node_cannot_read_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_write_page(
        struct fs_node *node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_flush(
        struct fs_node *node)
{
    return -EINVAL;
}
int
fs_node_cannot_getattr(
        struct fs_node *node,
        int attr,
        size_t *value)
{
    return -EINVAL;
}
int
fs_node_cannot_setattr(
        struct fs_node *node,
        int attr,
        size_t value)
{
    return -EINVAL;
}
int
fs_node_cannot_lookup(
        struct fs_node *node,
        const char *name,
        size_t *inode)
{
    return -EINVAL;
}
int
fs_node_cannot_mkfile(
        struct fs_node *node,
        const char *name,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_mkfifo(
        struct fs_node *node,
        const char *name,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_mkdir(
        struct fs_node *node,
        const char *name,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_node_cannot_link(
        struct fs_node *node,
        const char *name,
        size_t inode)
{
    return -EINVAL;
}
int
fs_node_cannot_symlink(
        struct fs_node *node,
        const char *name,
        const char *path)
{
    return -EINVAL;
}
int
fs_node_cannot_unlink(
        struct fs_node *node,
        const char *name)
{
    return -EINVAL;
}

