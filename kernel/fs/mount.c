
#include <kanawha/fs/mount.h>

#include <kanawha/assert.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/rwlock.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

static int
fs_mount_node_pcache_load_node(
        struct pcache *pcache,
        size_t index,
        struct pcache_node **out)
{
    int res;
    struct fs_mount *mnt =
        container_of(pcache, struct fs_mount, node_cache);
    struct fs_node *fs_node;
    fs_node = fs_node_create();
    fs_node->mount = mnt;
    res = fs_mount_load_node(mnt, index, fs_node);
    if(res)
    {
        kfree(fs_node);
        return res;
    }

    DEBUG_ASSERT(KERNEL_ADDR(out));
    *out = &fs_node->cache_node;

    return 0;
}
static int
fs_mount_node_pcache_unload_node(
        struct pcache *pcache,
        size_t index,
        struct pcache_node *node)
{
    int res;

    struct fs_mount *mnt =
        container_of(pcache, struct fs_mount, node_cache);

    struct fs_node *fs_node =
        container_of(node, struct fs_node, cache_node);

    res = fs_mount_unload_node(
            mnt,
            index,
            fs_node);
    if(res) {
        return res;
    }

    return 0;
}

static int
fs_mount_node_pcache_flush_node(
        struct pcache *pcache,
        size_t index,
        struct pcache_node *node)
{
    int res;

    struct fs_mount *mnt =
        container_of(pcache, struct fs_mount, node_cache);

    struct fs_node *fs_node =
        container_of(node, struct fs_node, cache_node);


    res = fs_node_flush(fs_node, 0);
    if(res) {
        return res;
    }

    res = fs_mount_sync(mnt);
    if(res) {
        return res;
    }

    return 0;
}

static struct pcache_ops
fs_mount_node_pcache_ops = {
    .load_node = fs_mount_node_pcache_load_node,
    .unload_node = fs_mount_node_pcache_unload_node,
    .flush_node = fs_mount_node_pcache_flush_node,
};

int
init_fs_mount_struct(struct fs_mount *mnt, struct fs_mount_ops *ops)
{
    int res;
    mnt->ops = ops;
    res = pcache_init(&mnt->node_cache, &fs_mount_node_pcache_ops);
    if(res) {
        return res;
    }
    return 0;
}

struct fs_node *
fs_mount_get_node(struct fs_mount *mnt, size_t node_index)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(mnt));
    struct pcache_node *pcache_node = NULL;
    res = pcache_lookup_node(
            &mnt->node_cache,
            node_index,
            &pcache_node);
    if(res) {
        return NULL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(pcache_node));

    struct fs_node *fs_node =
        container_of(pcache_node, struct fs_node, cache_node);

    return fs_node;
}

// Default Implementations

int
fs_mount_nop_sync(struct fs_mount *mnt)
{
    return 0;
}
