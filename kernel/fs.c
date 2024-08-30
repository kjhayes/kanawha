
#include <kanawha/fs.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_cache.h>
#include <kanawha/page_alloc.h>
#include <kanawha/vmem.h>
#include <kanawha/assert.h>

static DECLARE_SPINLOCK(fs_type_tree_lock);
static DECLARE_STREE(fs_type_tree);

static DECLARE_SPINLOCK(fs_active_mount_tree_lock);
static DECLARE_STREE(fs_active_mount_tree);

int
register_fs_type(
        struct fs_type *type,
        char *name)
{
    type->fs_type_node.key = name;
    return stree_insert(&fs_type_tree, &type->fs_type_node);
}

struct fs_type *
fs_type_find(const char *name)
{
    struct stree_node *node = stree_get(&fs_type_tree, name);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct fs_type, fs_type_node);
}

int
init_fs_mount_struct(
        struct fs_mount *mnt,
        struct fs_mount_ops *ops)
{
    mnt->ops = ops;
    atomic_bool_set_relaxed(&mnt->is_attached, 0);
    ptree_init(&mnt->node_cache);
    return 0;
}

int
fs_attach_mount(
        struct fs_mount *mnt,
        const char *name)
{
    int was_attached = atomic_bool_test_and_set(&mnt->is_attached);
    if(was_attached) {
        return -EEXIST;
    }
    mnt->attach_node.key = name;
    spin_lock(&fs_active_mount_tree_lock);
    int res = stree_insert(&fs_active_mount_tree, &mnt->attach_node);
    spin_unlock(&fs_active_mount_tree_lock);
    return res;
}

struct fs_mount *
fs_deattach_mount(
        const char *name)
{
    struct fs_mount *mnt = NULL;
    spin_lock(&fs_active_mount_tree_lock);
    struct stree_node *node =
        stree_get(&fs_active_mount_tree, name);

    if(node != NULL) {
        mnt = container_of(node, struct fs_mount, attach_node);
        atomic_bool_clear(&mnt->is_attached);
        stree_remove(
                &fs_active_mount_tree,
                name);
    }

    spin_unlock(&fs_active_mount_tree_lock);
    return mnt;
}

struct fs_mount *
fs_mount_lookup(const char *name)
{
    struct stree_node *node;
    spin_lock(&fs_active_mount_tree_lock);
    node = stree_get(&fs_active_mount_tree, name);
    spin_unlock(&fs_active_mount_tree_lock);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct fs_mount, attach_node);
}

int
fs_node_lookup(
        struct fs_mount *mnt,
        const char *path,
        size_t *out_index)
{
    int res;

    DEBUG_ASSERT(mnt != NULL);

    dprintk("fs_node_lookup: %s\n", path);

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        return res;
    }

    size_t path_len = strlen(path);
    char buf[path_len+1];
    memcpy(buf, path, path_len);
    buf[path_len] = '\0';

    for(size_t i = 0; i < path_len; i++) {
        buf[i] = buf[i] == '/' ? '\0' : buf[i];
    }

    char *cur_str = buf;
    char *buf_end = buf + path_len + 1;

    size_t cur_node_index = root_index;
    while(cur_str < buf_end) {
        struct fs_node *cur_dir;
        cur_dir = fs_mount_get_node(mnt, cur_node_index);

        if(cur_dir == NULL) {
            return -ENXIO;
        }

        int found_next_step = 0;
        size_t next_step;

        size_t cur_str_len = strlen(cur_str) + 1;
        char name_buf[cur_str_len + 1];

        size_t num_children;
        res = fs_node_attr(cur_dir, FS_NODE_ATTR_CHILD_COUNT, &num_children);
        if(res) {
            fs_mount_put_node(mnt, cur_dir);
            return res;
        }

        dprintk("fs_lookup: num_children = %ld, cur_str = %s\n", num_children, cur_str);
        for(size_t i = 0; i < num_children; i++)
        {
            dprintk("iteration = %ld\n", i);
            res = fs_node_child_name(cur_dir, i, name_buf, cur_str_len);
            if(res) {
                // Couldn't get the name of this child,
                // continue anyways
                eprintk("fs_node_lookup failed to get name of directory child (index=%d) (err=%s), continuing...\n",
                        i, errnostr(res));
                continue;
            }
            name_buf[cur_str_len] = '\0';

            int cmp = strcmp(cur_str, name_buf);
            if(cmp != 0) {
                dprintk("Checking node with name \"%s\"\n", name_buf);
                continue;
            }

            // This node has the correct name
            size_t child_index;
            res = fs_node_get_child(cur_dir, i, &child_index);
            if(res) {
                eprintk("fs_node_lookup found child with correct name, but failed to get fs_node! (err=%s)\n",
                        errnostr(res));
                return res;
            }
            found_next_step = 1;
            next_step = child_index;
            break;
        }

        // Go to the next string in the path, or "buf_end"
        res = fs_mount_put_node(mnt, cur_dir);
        if(res) {
            eprintk("fs_node_lookup failed to put directory node!\n");
            return res;
        }

        if(!found_next_step) {
            eprintk("fs_node_lookup failed to find file: \"%s\"\n", cur_str);
            return -ENXIO;
        }

        cur_str += (cur_str_len+1);

        cur_node_index = next_step;
    }

    if(out_index) {
        *out_index = cur_node_index;
    }
    return 0;
}

struct fs_node *
fs_mount_get_node(
        struct fs_mount *mnt,
        size_t node_index)
{
    struct fs_node *fs_node = NULL;
    struct ptree_node *node;
    spin_lock(&mnt->cache_lock);
    node = ptree_get(&mnt->node_cache, node_index);
    if(node == NULL) {
        fs_node = fs_mount_load_node(mnt, node_index);
        dprintk("fs_mount_load_node -> %p, ops = %p\n",
                fs_node, fs_node->ops);

        spinlock_init(&fs_node->page_lock);
        ptree_init(&fs_node->page_cache);

        fs_node->mount = mnt;
        fs_node->refcount = 1;
        ptree_init(&fs_node->page_cache);

        int res;
        res = ptree_insert(&mnt->node_cache, &fs_node->cache_node, node_index);
        if(res) {
            fs_mount_unload_node(mnt, fs_node);
            fs_node = NULL;
        }

    } else {
        fs_node = container_of(node, struct fs_node, cache_node);
    }
    spin_unlock(&mnt->cache_lock);
    return fs_node;
}

int
fs_mount_put_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    int res;
    size_t index = node->cache_node.key;
    spin_lock(&mnt->cache_lock);
    if(node->refcount <= 0) {
        res = -EINVAL;
        goto err;
    }
    else if(node->refcount == 1) {
        // We're removing the last reference

        res = fs_node_flush_all_pages(node);
        if(res) {
            goto err;
        }

        // Flush the node (if we had a reclaimable list,
        //                 we might be able to put this off for a bit)
        res = fs_node_flush(node);
        if(res) {
            goto err;
        }


        // TODO
        // Add this node to a list of reclaimable nodes
        // (For now we'll just free it, so our "cache" doesn't do much caching)
        struct ptree_node *removed = ptree_remove(&mnt->node_cache, index);
        if(removed != &node->cache_node) {
            if(removed != NULL) {
                // ERROR
                // Try to re-insert the incorrectly removed node
                ptree_insert(&mnt->node_cache, removed, removed->key);
                res = -EINVAL;
                goto err;
            }
        }
        res = fs_mount_unload_node(mnt, node);
        if(res) {
            eprintk("Filesystem failed to unload fs_node!\n");
            goto err;
        }

    } else {
        node->refcount--;
    }
    spin_unlock(&mnt->cache_lock);
    return 0;

err:
    spin_unlock(&mnt->cache_lock);
    return res;
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
fs_path_lookup(
        const char *path,
        struct fs_mount **mnt_out,
        struct fs_node **node_out)
{
    int res;
    size_t pathlen = strlen(path);

    size_t colon = 0;
    while(colon < pathlen) {
        if(path[colon] == ':') {
            break;
        }
        colon++;
    }

    struct fs_mount *mnt;

    if(colon >= pathlen) {
        // No mount specified,
        // use the default
        mnt = fs_mount_lookup("");
    } else {
        char buffer[colon+1];
        memcpy(buffer, path, colon);
        buffer[colon] = '\0';

        mnt = fs_mount_lookup(buffer);
        path += (colon+1);
    }

    if(mnt == NULL) {
        // Couldn't find the mount
        return -ENXIO;
    }

    size_t node_index;
    res = fs_node_lookup(mnt, path, &node_index);
    if(res) {
        // Couldn't find the node
        return res;
    }

    struct fs_node *node;
    node = fs_mount_get_node(mnt, node_index);

    if(node == NULL) {
        return -EBADF;
    }

    if(mnt_out) {
        *mnt_out = mnt;
    }
    if(node_out) {
        *node_out = node;
    }

    return 0;
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


/*
 * stree Wrapper Mount
 */

static int
stree_fs_mount_root_index(
        struct fs_mount *mnt,
        size_t *index)
{
    *index = 0;
    return 0;
}

static struct fs_node *
stree_fs_mount_load_node(
        struct fs_mount *mount,
        size_t node_index)
{
    struct stree_fs_mount *mnt =
        container_of(mount, struct stree_fs_mount, mount);

    spin_lock(&mnt->lock);
    if(node_index == 0) {
        spin_unlock(&mnt->lock);
        return &mnt->root_node.fs_node;
    }

    struct ptree_node *pnode =
        ptree_get(&mnt->node_index_tree, node_index);
    if(pnode == NULL) {
        spin_unlock(&mnt->lock);
        return NULL;
    }
    struct stree_fs_node *node =
        container_of(pnode, struct stree_fs_node, index_node);

    spin_unlock(&mnt->lock);
    return &node->fs_node;
}

static int
stree_fs_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    return 0;
}

static struct fs_mount_ops
stree_fs_mount_ops = {
    .root_index = stree_fs_mount_root_index,
    .load_node = stree_fs_mount_load_node,
    .unload_node = stree_fs_mount_unload_node,
};

static int
stree_fs_node_attr(
        struct fs_node *node,
        int attr_index,
        size_t *attr_value)
{
    struct stree_fs_mount *mnt =
        container_of(node, struct stree_fs_mount, root_node.fs_node);

    spin_lock(&mnt->lock);

    switch(attr_index) {
        case FS_NODE_ATTR_MAX_OFFSET_END:
        case FS_NODE_ATTR_MAX_OFFSET:
            *attr_value = 0;
            break;
        case FS_NODE_ATTR_CHILD_COUNT:
            *attr_value = mnt->num_children;
            break;
        default:
            spin_unlock(&mnt->lock);
            return -EINVAL;
    }

    spin_unlock(&mnt->lock);
    return 0;
}

int
stree_fs_node_get_child(
        struct fs_node *fs_node,
        size_t child_index,
        size_t *node_index)
{
    struct stree_fs_mount *mnt =
        container_of(fs_node, struct stree_fs_mount, root_node.fs_node);

    spin_lock(&mnt->lock);
    struct ptree_node *pnode = ptree_get_first(&mnt->node_index_tree);

    // Our root node should be index 0
    DEBUG_ASSERT(pnode != NULL);
    pnode = ptree_get_next(pnode);

    int index = 0;

    while(index < child_index && pnode != NULL) {
        pnode = ptree_get_next(pnode);
        index++;
    }

    if(pnode == NULL) {
        spin_unlock(&mnt->lock);
        return -ENXIO;
    }

    if(index != child_index) {
        spin_unlock(&mnt->lock);
        return -ENXIO;

    }

    *node_index = pnode->key;

    spin_unlock(&mnt->lock);

    return 0;
}

int
stree_fs_node_child_name(
        struct fs_node *fs_node,
        size_t index,
        char *buf,
        size_t buf_size) 
{
    struct stree_fs_mount *mnt =
        container_of(fs_node, struct stree_fs_mount, root_node.fs_node);

    spin_lock(&mnt->lock);

    // Root node
    struct ptree_node *pnode = ptree_get_first(&mnt->node_index_tree);
    DEBUG_ASSERT(pnode != NULL);
    pnode = ptree_get_next(pnode);

    while(index > 0 && pnode != NULL) {
        pnode = ptree_get_next(pnode);
        index--;
    }

    if(pnode == NULL || index != 0) {
        spin_unlock(&mnt->lock);
        return -ENXIO;
    }

    struct stree_fs_node *node =
        container_of(pnode, struct stree_fs_node, index_node);

    strncpy(buf, node->stree_node.key, buf_size);

    spin_unlock(&mnt->lock);

    return 0; 
}

static struct fs_node_ops
stree_fs_node_ops = {
    .read = unreadable_fs_node_read,
    .write = immutable_fs_node_write,
    .flush = writethrough_fs_node_flush,
    
    .attr = stree_fs_node_attr,
    .get_child = stree_fs_node_get_child,
    .child_name = stree_fs_node_child_name,
};

int
stree_fs_mount_init(
        struct stree_fs_mount *mnt)
{
    int res;

    spinlock_init(&mnt->lock);
    stree_init(&mnt->node_tree);
    ptree_init(&mnt->node_index_tree);

    mnt->root_node.fs_node.mount = &mnt->mount;
    mnt->root_node.fs_node.ops = &stree_fs_node_ops;
    mnt->num_children = 0;

    ptree_insert(&mnt->node_index_tree, &mnt->root_node.index_node, 0);

    res = init_fs_mount_struct(
            &mnt->mount,
            &stree_fs_mount_ops);
    if(res) {
        return res;
    }

    return 0;
}

int
stree_fs_mount_deinit(
        struct stree_fs_mount *mnt)
{
    return -EUNIMPL;
}

struct fs_mount *
stree_fs_mount_get_mount(
        struct stree_fs_mount *mnt)
{
    return &mnt->mount;
}

int
stree_fs_mount_insert(
        struct stree_fs_mount *mnt,
        struct stree_fs_node *node,
        const char *name)
{
    int res;

    spin_lock(&mnt->lock);
    node->fs_node.mount = &mnt->mount;

    node->stree_node.key = kstrdup(name);
    dprintk("stree_fs_mount_insert -> %s\n", node->stree_node.key);
    res = stree_insert(&mnt->node_tree, &node->stree_node);
    if(res) {
        kfree((void*)node->stree_node.key);
        return res;
    }

    res = ptree_insert_any(&mnt->node_index_tree, &node->index_node);
    if(res) {
        stree_remove(&mnt->node_tree, name);
        kfree((void*)node->stree_node.key);
        spin_unlock(&mnt->lock);
        return res;
    }

    dprintk("STREE FS NODE INSTERTED WITH FS INDEX %lld\n", (ull_t)node->index_node.key);

    mnt->num_children++;

    spin_unlock(&mnt->lock);

    return 0;
}

int
stree_fs_mount_remove(
        struct stree_fs_mount *mnt,
        struct stree_fs_node *node)
{
    int res;
    spin_lock(&mnt->lock);

    struct ptree_node * premoved =
        ptree_remove(&mnt->node_index_tree, node->index_node.key);
    DEBUG_ASSERT(premoved == &node->index_node);

    struct stree_node *sremoved =
        stree_remove(&mnt->node_tree, node->stree_node.key);
    DEBUG_ASSERT(sremoved == &node->stree_node);

    kfree((void*)node->stree_node.key);

    mnt->num_children--;

    spin_unlock(&mnt->lock);
    return 0;
}

#define FS_DUMP_NODES_MAX_NAMELEN 128

static void
fs_dump_nodes_recursive(
        printk_f *printer,
        struct fs_mount *mnt,
        struct fs_node *node,
        int stop_on_zero,
        int num_tabs)
{
    if(stop_on_zero == 0) {
        return;
    }

    int res;

#define PRINT (*printer)
#define PRINT_TABS()\
    do {\
        for(int i = 0; i < num_tabs; i++) {\
            PRINT("\t");\
        }\
    } while(0)

    size_t num_children;
    res = fs_node_attr(node, FS_NODE_ATTR_CHILD_COUNT, &num_children);
    if(res) {
        PRINT_TABS();
        PRINT("[Failed to get number of child nodes (err=%s)\n",
                errnostr(res));
        return;
    }

    char name_buf[FS_DUMP_NODES_MAX_NAMELEN+1];

    for(size_t child_index = 0; child_index < num_children; child_index++)
    {
        PRINT_TABS();
        PRINT("(%lld)", (sll_t)child_index);

        res = fs_node_child_name(
                node,
                child_index,
                name_buf,
                FS_DUMP_NODES_MAX_NAMELEN);
        if(res) {
            PRINT(" [fs_node_child_name returned %s]\n",
                    errnostr(res));
            continue;
        }

        PRINT(" \"%s\"", name_buf);

        size_t child_node_index;
        res = fs_node_get_child(node, child_index, &child_node_index);
        if(res) {
            PRINT(" [fs_node_get_child returned %s]\n",
                    errnostr(res));
            continue;
        }

        PRINT(" (index=%lld)", (sll_t)child_node_index);

        struct fs_node *child = fs_mount_get_node(mnt, child_node_index);
        if(child == NULL) {
            PRINT(" [fs_mount_get_node returned NULL]\n");
            continue;
        }

        PRINT("\n");

        fs_dump_nodes_recursive(
                printer,
                mnt,
                child,
                stop_on_zero-1,
                num_tabs+1);

        fs_mount_put_node(mnt, child);
        if(child == NULL) {
            PRINT_TABS();
            PRINT(" [fs_mount_put_node returned NULL]\n");
            continue;
        }
    }

#undef PRINT_TABS
#undef PRINT
}

void
fs_dump_attached_mounts(
        printk_f *printer,
        int depth)
{
#define PRINT (*printer)

    int res;
    spin_lock(&fs_active_mount_tree_lock);
    struct stree_node *attached_node;
    attached_node = stree_get_first(&fs_active_mount_tree);

    while(attached_node != NULL)
    {
        struct fs_mount *mnt =
            container_of(attached_node, struct fs_mount, attach_node);

        PRINT("%s:", mnt->attach_node.key);

        size_t root_index;
        res = fs_mount_root_index(mnt, &root_index);
        if(res) {
            PRINT(" [Failed to get root node (err=%s)]\n",
                    errnostr(res));
            goto next_iter;
        }
        
        struct fs_node *root = fs_mount_get_node(mnt, root_index);
        if(root == NULL) {
            PRINT(" [root_index=0x%llx, root=NULL]\n",
                    (ull_t)root_index);
            goto next_iter;
        }

        PRINT(" [root_index=0x%llx]\n",
                (ull_t)root_index);

        fs_dump_nodes_recursive(
                printer,
                mnt,
                root,
                depth,
                1);

        res = fs_mount_put_node(mnt, root);
        if(res) {
            PRINT("[fs_mount_put_node returned %s on root node]\n",
                    errnostr(res));
            goto next_iter;
        }

next_iter:
        attached_node = stree_get_next(attached_node);
    }

    spin_unlock(&fs_active_mount_tree_lock);
    return;

#undef PRINT
}

