
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/assert.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>

int
fs_node_get(struct fs_node *node)
{
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

order_t
fs_node_page_order(
        struct fs_node *node)
{
    return VMEM_MIN_PAGE_ORDER;
}

struct fs_page *
fs_node_get_page(
        struct fs_node *node,
        uintptr_t pfn)
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

        order_t order = fs_node_page_order(node);
        res = page_alloc(order, &page->paddr, 0);
        if(res) {
            spin_unlock(&node->page_lock);
            kfree(page);
            return NULL;
        }

        size_t amount = 1ULL<<order;
        fs_node_read(
                node,
                (void*)__va(page->paddr),
                &amount,
                pfn<<order);

        if(amount == 0) {
            spin_unlock(&node->page_lock);
            page_free(order, page->paddr);
            kfree(page);
            return NULL;
        }

        page->order = order;
        page->size = amount;
        page->flags = 0;

        ptree_insert(&node->page_cache, &page->tree_node, pfn);

    } else {
        page = container_of(pnode, struct fs_page, tree_node);
    }

    spin_unlock(&node->page_lock);
    return page;
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
            res = fs_node_flush_page(
                    node,
                    page);
            if(res) {
                page->pins++;
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

static int
fs_node_flush_page_lockless(
        struct fs_node *node,
        struct fs_page *page)
{
    int res;

    size_t amount = page->size;

    res = fs_node_write(
            node,
            (void*)__va(page->paddr),
            &amount,
            page->tree_node.key << page->order);

    if(res) {
        return res;
    }

    if(amount < page->size) {
        return -EAGAIN;
    }

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
childless_fs_node_get_child(
        struct fs_node *node,
        size_t child_index,
        size_t *node_index)
{
    return -ENXIO;
}
int
childless_fs_node_child_name(
        struct fs_node * node,
        size_t child_index,
        char *buf,
        size_t buf_size)
{
    return -ENXIO;
}

int
unreadable_fs_node_read(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        uintptr_t offset)
{
    return -EINVAL;
}

int
immutable_fs_node_write(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        uintptr_t offset)
{
    return -EINVAL;
}

int
writethrough_fs_node_flush(
        struct fs_node *node)
{
    return 0;
}


