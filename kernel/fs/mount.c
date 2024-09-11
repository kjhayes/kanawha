
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/stddef.h>

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
