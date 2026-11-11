
#include <kanawha/pcache.h>
#include <kanawha/ops.h>
#include <kanawha/atomic.h>
#include <kanawha/stddef.h>

#define pcache_node_tree_lock_init(__cache)\
    irq_lock_init(&(__cache)->node_tree_lock)
#define pcache_node_tree_lock_acquire(__cache)\
    irq_lock_acquire(&(__cache)->node_tree_lock)
#define pcache_node_tree_lock_release(__cache)\
    irq_lock_release(&(__cache)->node_tree_lock)

int
pcache_init(
        struct pcache *cache,
        struct pcache_ops * ops)
{
    cache->ops = ops;
    pcache_node_tree_lock_init(cache);
    ptree_init(&cache->node_tree);
    return 0;
}
int
pcache_deinit(
        struct pcache *cache)
{
    pcache_node_tree_lock_acquire(cache);
    struct ptree_node *node = ptree_get_first(&cache->node_tree);
    if(node != NULL) {
        pcache_node_tree_lock_release(cache);
        return -EINVAL;
    }
    // Do not release the lock: no one else can add to this pcache
    return 0;
}

struct pcache *
pcache_node_get_cache(
        struct pcache_node *node)
{
    return node->pcache;
}

static inline void
pcache_node_get_possibly_unreferenced(
        struct pcache_node *node)
{
    atomic_val_t old = atomic_fetch_inc(&node->refcount);
    if(old == 0) {
        // printk("Reviving pcache_node!\n");
    }
}
void
pcache_node_get(
        struct pcache_node *node)
{
    atomic_val_t old = atomic_fetch_inc(&node->refcount);
    DEBUG_ASSERT(old > 0);
}
void
pcache_node_put(
        struct pcache_node *node)
{
    int res;

    struct pcache *cache = pcache_node_get_cache(node);
    size_t index = pcache_node_get_index(node);

    pcache_node_tree_lock_acquire(cache);
    atomic_val_t old = atomic_fetch_dec(&node->refcount);
    if(old == 1) {
        // TODO: Add this to a LRU cache instead of immediately freeing
        //struct ptree_node *removed;
        //removed = ptree_remove(&cache->node_tree, index);
        //DEBUG_ASSERT(removed == &node->cache_node);
        //node->pcache = NULL;

        //res = pcache_unload_node(
        //        cache,
        //        index,
        //        node);
        //if(res) {
        //    eprintk("pcache_node_put: failed to unload node! (err=%e)\n",
        //            res);
        //}
    }
    pcache_node_tree_lock_release(cache);
}

int
pcache_lookup_node(
        struct pcache *cache,
        size_t index,
        struct pcache_node **out)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(out));

    pcache_node_tree_lock_acquire(cache);

    struct pcache_node *pcache_node = NULL;
    struct ptree_node *candidate_pnode;
    candidate_pnode = ptree_get(&cache->node_tree, index);
    if(candidate_pnode == NULL) {
        // This node is not currently loaded
        res = pcache_load_node(
                cache,
                index,
                &pcache_node);
        if(res) {
            pcache_node_tree_lock_release(cache);
            return res;
        }
        pcache_node->pcache = cache;
        atomic_set_relaxed(&pcache_node->refcount, 1);
        res = ptree_insert(&cache->node_tree, &pcache_node->cache_node, index);
        if(res) {
            if(pcache_unload_node(cache, index, pcache_node)) {
                panic("pcache: failed to unload node after failing insert!\n");
            }
            pcache_node_tree_lock_release(cache);
            return res;
        }

    } else {
        pcache_node =
            container_of(
                    candidate_pnode,
                    struct pcache_node,
                    cache_node);
        pcache_node_get_possibly_unreferenced(pcache_node);
    }

    if(pcache_node == NULL) {
        pcache_node_tree_lock_release(cache);
        return -ENXIO;
    }

    *out = pcache_node;

    pcache_node_tree_lock_release(cache);

    return 0;
}

size_t
pcache_node_get_index(
        struct pcache_node *node)
{
    return node->cache_node.key;
}

int
pcache_flush_all(
        struct pcache *pcache)
{
    int res;
    pcache_node_tree_lock_acquire(pcache);

    unsigned long num_failures = 0;

    struct ptree_node *iter = ptree_get_first(&pcache->node_tree);
    while(iter) {
        struct pcache_node *pnode =
            container_of(iter, struct pcache_node, cache_node);
        res = pcache_flush_node(
                pcache,
                pcache_node_get_index(pnode),
                pnode);
        if(res) {
            num_failures++;
        }
        iter = ptree_get_next(iter);
    }

    pcache_node_tree_lock_release(pcache);

    if(num_failures != 0) {
        return -EFAULT;
    }

    return 0;
}

