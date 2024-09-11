
#include <kanawha/fs/stree.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

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

