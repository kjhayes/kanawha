
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/types.h>

int
vfs_mount_load_node(struct fs_mount *fs_mnt,
                    size_t inode,
                    struct fs_node *fs_node)
{
    dprintk("vfs_mount_load_node(inode=%p)\n", inode);

    struct vfs_mount *mnt = container_of(fs_mnt, struct vfs_mount, fs_mount);

    struct ptree_node *pnode;

    irq_lock_acquire(&mnt->lock);
    pnode = ptree_get(&mnt->inode_tree, inode);
    if(pnode == NULL)
    {
        irq_lock_release(&mnt->lock);
        return -ENXIO;
    }
    struct vfs_node *node = container_of(pnode, struct vfs_node, inode_node);

    node->fs_node = fs_node;
    fs_node->backing.node_ops = node->fs_node_ops;
    fs_node->backing.file_ops = node->fs_file_ops;
    fs_node->backing.priv_state = node;

    irq_lock_release(&mnt->lock);

    return 0;
}

int
vfs_mount_unload_node(struct fs_mount *fs_mount,
                      size_t index,
                      struct fs_node *fs_node)
{
    dprintk("vfs_mount_unload_node(fs_node=%p)\n", fs_node);

    struct vfs_mount *mnt = container_of(fs_mount, struct vfs_mount, fs_mount);

    struct vfs_node *node = fs_node->backing.priv_state;

    irq_lock_acquire(&mnt->lock);
    DEBUG_ASSERT(node->fs_node == fs_node);
    node->fs_node = NULL;
    irq_lock_release(&mnt->lock);

    return 0;
}

int
vfs_mount_root_index(struct fs_mount *fs_mnt, size_t *root_out)
{
    dprintk("vfs_mount_root_index\n");

    struct vfs_mount *mnt = container_of(fs_mnt, struct vfs_mount, fs_mount);
    *root_out = mnt->root_inode;
    return 0;
}

static struct fs_mount_ops vfs_mount_ops = {
    .load_node = vfs_mount_load_node,
    .unload_node = vfs_mount_unload_node,
    .root_index = vfs_mount_root_index,
    .sync = fs_mount_nop_sync,
};

// Internal structure to maintain list of links
// "vfs_node.children_list"
struct vfs_link
{
    struct stree_node stree_node;

    char *name;
    size_t inode;
};

int
vfs_dir_lookup(struct fs_node *fs_node,
               const char *name,
               size_t *inode,
               char *sym_buffer,
               size_t sym_buflen)
{
    dprintk("vfs_dir_lookup(name=%s)\n", name);

    struct vfs_node *node = fs_node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(fs_node));
    DEBUG_ASSERT(KERNEL_ADDR(node));

    if(strcmp(name, ".") == 0)
    {
        *inode = fs_node->cache_node.key;
        return FS_NODE_LOOKUP_HARD;
    }

    irq_lock_acquire(&node->hierarchy_lock);

    struct stree_node *snode = stree_get(&node->children_tree, name);
    if(snode == NULL)
    {
        irq_lock_release(&node->hierarchy_lock);
        return -ENXIO;
    }

    struct vfs_link *link = container_of(snode, struct vfs_link, stree_node);

    DEBUG_ASSERT(KERNEL_ADDR(snode));
    DEBUG_ASSERT(KERNEL_ADDR(link));

    if(inode != NULL)
    {
        *inode = link->inode;
    }

    irq_lock_release(&node->hierarchy_lock);

    return FS_NODE_LOOKUP_HARD;
}

int
vfs_dir_begin(struct file *dir)
{
    dprintk("vfs_dir_begin\n");

    dir->dir_offset = 0;
    return 0;
}

int
vfs_dir_next(struct file *dir)
{
    dprintk("vfs_dir_next\n");

    struct fs_node *fs_node = fs_path_get_fs_node(dir->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    struct vfs_node *node = fs_node->backing.priv_state;

    dir->dir_offset++;
    if(dir->dir_offset == node->children_count)
    {
        return -ENXIO;
    }
    if(dir->dir_offset > node->children_count)
    {
        return -EINVAL;
    }

    return 0;
}

int
vfs_dir_readattr(struct file *file, int attr, size_t *value)
{
    dprintk("vfs_dir_readattr\n");

    return -EUNIMPL;
}

int
vfs_dir_readname(struct file *dir, char *name_buf, size_t buf_len)
{
    dprintk("vfs_dir_readname\n");

    struct fs_node *fs_node = fs_path_get_fs_node(dir->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    struct vfs_node *node = fs_node->backing.priv_state;

    irq_lock_acquire(&node->hierarchy_lock);
    if(dir->dir_offset + 1 > node->children_count)
    {
        irq_lock_release(&node->hierarchy_lock);
        dprintk("Not searching (dir_offset=0x%lx, children_count=0x%lx)\n",
                dir->dir_offset,
                node->children_count);
        return -ENXIO;
    }

    struct stree_node *snode = stree_get_first(&node->children_tree);
    for(size_t i = 0; i < dir->dir_offset; i++)
    {
        if(snode == NULL)
        {
            break;
        }
        snode = stree_get_next(snode);
    }

    if(snode == NULL)
    {
        irq_lock_release(&node->hierarchy_lock);
        dprintk("Failed after search\n");
        return -ENXIO;
    }

    struct vfs_link *link = container_of(snode, struct vfs_link, stree_node);
    strncpy(name_buf, link->name, buf_len);

    dprintk("link=%s\n", link->name);

    irq_lock_release(&node->hierarchy_lock);
    return 0;
}

static struct fs_node_ops vfs_root_node_ops = {
    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(vfs_root_node_ops);
static struct fs_file_ops vfs_root_file_ops = {
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(vfs_root_file_ops);

struct vfs_mount *
vfs_mount_create(void)
{
    int res;

    struct vfs_mount *mnt = kzmalloc(sizeof(struct vfs_mount), KM_KERNEL);
    if(mnt == NULL)
    {
        return NULL;
    }

    irq_lock_init(&mnt->lock);
    ptree_init(&mnt->inode_tree);
    mnt->num_nodes = 0;

    init_fs_mount_struct(&mnt->fs_mount, &vfs_mount_ops);

    mnt->root_node.fs_node_ops = &vfs_root_node_ops;
    mnt->root_node.fs_file_ops = &vfs_root_file_ops;
    res = vfs_mount_insert_node(mnt, &mnt->root_node, &mnt->root_inode);
    if(res)
    {
        kfree(mnt);
        return NULL;
    }

    return mnt;
}

int
vfs_mount_destroy(struct vfs_mount *mnt)
{
    return -EUNIMPL;
}

int
vfs_mount_insert_node(struct vfs_mount *mnt,
                      struct vfs_node *node,
                      size_t *inode_index_out)
{
    int res;
    irq_lock_acquire(&mnt->lock);

    res = ptree_insert_any(&mnt->inode_tree, &node->inode_node);
    if(res)
    {
        irq_lock_release(&mnt->lock);
        return res;
    }
    dprintk("vfs_mount_insert_node -> %p\n", node->inode_node.key);

    irq_lock_init(&node->hierarchy_lock);
    stree_init(&node->children_tree);
    node->children_count = 0;
    node->fs_node = NULL;
    mnt->num_nodes++;

    DEBUG_ASSERT(mnt->num_nodes > 0);

    if(inode_index_out != NULL)
    {
        *inode_index_out = node->inode_node.key;
    }

    irq_lock_release(&mnt->lock);
    return 0;
}

int
vfs_mount_remove_node(struct vfs_mount *mnt, struct vfs_node *node)
{
    int res;
    irq_lock_acquire(&mnt->lock);

    struct ptree_node *rem =
        ptree_remove(&mnt->inode_tree, node->inode_node.key);
    mnt->num_nodes--;

    res = vfs_node_unlink_all(node);
    DEBUG_ASSERT(res == 0); // We'd leak memory otherwise

    if(node->fs_node != NULL)
    {
        fs_node_deattach_backing(node->fs_node);
        node->fs_node = NULL;
    }

    irq_lock_release(&mnt->lock);

    return 0;
}

int
vfs_mount_link_root(struct vfs_mount *mnt, const char *name, size_t inode)
{
    return vfs_node_link(&mnt->root_node, name, inode);
}

int
vfs_mount_unlink_root(struct vfs_mount *mnt, const char *name)
{
    return vfs_node_unlink(&mnt->root_node, name);
}

int
vfs_node_link(struct vfs_node *node, const char *name, size_t inode)
{
    int res;

    dprintk("vfs_node_link(%s, inode=0x%llx)\n", name, inode);

    irq_lock_acquire(&node->hierarchy_lock);

    struct vfs_link *link = kzmalloc(sizeof(struct vfs_link), KM_KERNEL);
    if(link == NULL)
    {
        irq_lock_release(&node->hierarchy_lock);
        return -ENOMEM;
    }

    link->name = kstrdup(name);
    link->inode = inode;
    link->stree_node.key = link->name;

    res = stree_insert(&node->children_tree, &link->stree_node);
    if(res)
    {
        kfree(link->name);
        kfree(link);
        irq_lock_release(&node->hierarchy_lock);
        return res;
    }

    node->children_count++;

    irq_lock_release(&node->hierarchy_lock);
    return 0;
}

int
vfs_node_unlink(struct vfs_node *node, const char *name)
{
    irq_lock_acquire(&node->hierarchy_lock);

    DEBUG_ASSERT(node->children_count > 0);

    struct stree_node *rem = stree_remove(&node->children_tree, name);
    DEBUG_ASSERT(KERNEL_ADDR(rem));

    struct vfs_link *link = container_of(rem, struct vfs_link, stree_node);

    kfree(link->name);
    kfree(link);

    node->children_count--;

    irq_lock_release(&node->hierarchy_lock);
    return 0;
}

// Unlinks all children of this node
int
vfs_node_unlink_all(struct vfs_node *node)
{
    irq_lock_acquire(&node->hierarchy_lock);

    struct stree_node *snode = stree_get_first(&node->children_tree);
    while(snode)
    {
        struct stree_node *rem = stree_remove(&node->children_tree, snode->key);
        DEBUG_ASSERT(rem == snode);

        struct vfs_link *link =
            container_of(snode, struct vfs_link, stree_node);
        kfree(link->name);
        kfree(link);

        snode = stree_get_first(&node->children_tree);
    }

    node->children_count = 0;

    irq_lock_release(&node->hierarchy_lock);
    return 0;
}

int
vfs_mount_insert_node_and_link_root(struct vfs_mount *mnt,
                                    struct vfs_node *node,
                                    const char *name)
{
    int res;

    size_t inode;
    res = vfs_mount_insert_node(mnt, node, &inode);
    if(res)
    {
        return res;
    }

    res = vfs_mount_link_root(mnt, name, inode);
    if(res)
    {
        vfs_mount_remove_node(mnt, node);
        return res;
    }

    return 0;
}
