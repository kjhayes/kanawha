
#include <kanawha/fs/mount.h>

#include <kanawha/fs/node.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/rwlock.h>

static int
fs_unload_node(
        struct fs_node *node)
{
    return fs_mount_unload_node(node->mount, node->cache_node.key, node);
}

int
init_fs_mount_struct(
        struct fs_mount *mnt,
        struct fs_mount_ops *ops)
{
    mnt->ops = ops;
    spinlock_init(&mnt->cache_lock);
    ptree_init(&mnt->node_cache);
    return 0;
}

struct fs_node *
fs_mount_get_node(
        struct fs_mount *mnt,
        size_t node_index)
{
    int res;

    struct fs_node *fs_node = NULL;
    struct ptree_node *node;

    DEBUG_ASSERT(KERNEL_ADDR(mnt));

    spin_lock(&mnt->cache_lock);

    node = ptree_get(&mnt->node_cache, node_index);

    if(node == NULL)
    {
	fs_node = kzmalloc(sizeof(*fs_node), KM_KERNEL);
	if(fs_node == NULL) {
	    return NULL;
	}

	rlock_init(&fs_node->backing_lock);

        spinlock_init(&fs_node->page_lock);
        ptree_init(&fs_node->page_cache);

        fs_node->mount = mnt;
        fs_node->refcount = 1;

        res = fs_mount_load_node(mnt, node_index, fs_node);
        if(res) {
	    kfree(fs_node);
            spin_unlock(&mnt->cache_lock);
            return NULL;
        }

        res = ptree_insert(&mnt->node_cache, &fs_node->cache_node, node_index);
        if(res) {
	    fs_mount_unload_node(mnt, node_index, fs_node);
	    kfree(fs_node);
            spin_unlock(&mnt->cache_lock);
	    return NULL;
        }

    } else {
        DEBUG_ASSERT(KERNEL_ADDR(node));
        fs_node = container_of(node, struct fs_node, cache_node);
        fs_node->refcount++;
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

        res = fs_node_flush_all_fs_pages(node);
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

        node->refcount = 0;

        res = fs_unload_node(node);
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

int
fs_mount_begin_unlinking_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    spin_lock(&mnt->cache_lock);
    if(node->refcount > 1) {
       spin_unlock(&mnt->cache_lock);
       return -EBUSY;
    }

    return 0;
}

int
fs_mount_end_unlinking_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    int res;

    node->refcount--;
    DEBUG_ASSERT(node->refcount == 0);

    size_t index = node->cache_node.key;

    struct ptree_node *removed = ptree_remove(&mnt->node_cache, index);
    DEBUG_ASSERT(removed == &node->cache_node);

    res = fs_unload_node(node);
    if(res) {
        eprintk("Filesystem failed to unload fs_node!\n");
        spin_unlock(&mnt->cache_lock);
        return res;
    }

    spin_unlock(&mnt->cache_lock);
    return 0;
}

// Default Implementations

int
fs_mount_nop_sync(
        struct fs_mount *mnt)
{
    return 0;
}

