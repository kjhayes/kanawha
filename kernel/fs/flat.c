
#include <kanawha/fs/flat.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

struct fs_node *
flat_mount_load_node(
        struct fs_mount *mnt,
        size_t inode)
{
    dprintk("flat_mount_load_node inode=%p\n", inode);
    struct flat_mount *fmnt =
        container_of(mnt, struct flat_mount, fs_mount);

    struct ptree_node *pnode;

    spin_lock(&fmnt->lock);
    pnode = ptree_get(&fmnt->inode_tree, inode);
    spin_unlock(&fmnt->lock);

    if(pnode == NULL) {
        return NULL;
    }

    struct flat_node *fnode =
        container_of(pnode, struct flat_node, inode_node);

    dprintk("returing\n");
    return &fnode->fs_node;
}

int
flat_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    struct flat_node *fnode =
        container_of(node, struct flat_node, fs_node);
    return 0;
}

int
flat_mount_root_index(
        struct fs_mount *mnt,
        size_t *root_out)
{
    struct flat_mount *fmnt =
        container_of(mnt, struct flat_mount, fs_mount);
    *root_out = fmnt->root_node.inode_node.key;
    return 0;
}

static struct fs_mount_ops
flat_mount_ops = {
    .load_node = flat_mount_load_node,
    .unload_node = flat_mount_unload_node,
    .root_index = flat_mount_root_index,
};

int
flat_dir_lookup(
        struct fs_node *fs_node,
        const char *name,
        size_t * inode)
{
    struct flat_node *fnode =
        container_of(fs_node, struct flat_node, fs_node);

    DEBUG_ASSERT(fnode->inode_node.key == 0);

    struct flat_mount *fmnt =
        container_of(fnode, struct flat_mount, root_node);

    spin_lock(&fmnt->lock);

    struct stree_node *snode =
        stree_get(&fmnt->lookup_tree, name);
    if(snode == NULL) {
        spin_unlock(&fmnt->lock);
        return -ENXIO;
    }

    struct flat_node *found =
        container_of(snode, struct flat_node, lookup_node);
    
    *inode = found->inode_node.key;

    spin_unlock(&fmnt->lock);
    return 0;
}

static int
flat_dir_iter_begin(
        struct file *dir)
{
    struct fs_node *fs_node =
        dir->path->fs_node;
    struct flat_node *fnode =
        container_of(fs_node, struct flat_node, fs_node);

    DEBUG_ASSERT(fnode->inode_node.key == 0);

    struct flat_mount *fmnt =
        container_of(fnode, struct flat_mount, root_node);

    spin_lock(&fmnt->lock);
   
    dir->dir_offset = 0;
    if(fmnt->num_nodes == 0) {
        spin_unlock(&fmnt->lock);
        return -ENXIO;
    }

    spin_unlock(&fmnt->lock);
    return 0;
}

static int
flat_dir_iter_next(
        struct file *dir)
{
    struct fs_node *fs_node =
        dir->path->fs_node;
    struct flat_node *fnode =
        container_of(fs_node, struct flat_node, fs_node);

    DEBUG_ASSERT(fnode->inode_node.key == 0);

    struct flat_mount *fmnt =
        container_of(fnode, struct flat_mount, root_node);

    spin_lock(&fmnt->lock);

    if(dir->dir_offset >= (fmnt->num_nodes-1)) {
        spin_unlock(&fmnt->lock);
        return -ENXIO;
    }

    dir->dir_offset++;

    spin_unlock(&fmnt->lock);

    return 0;
}

static int
flat_dir_iter_readattr(
        struct file *file,
        int attr,
        size_t *value)
{
    return -EINVAL;
}

static int
flat_dir_iter_readname(
        struct file *dir,
        char *name_buf,
        size_t buf_len)
{
    struct fs_node *fs_node =
        dir->path->fs_node;
    struct flat_node *fnode =
        container_of(fs_node, struct flat_node, fs_node);

    DEBUG_ASSERT(fnode->inode_node.key == 0);

    struct flat_mount *fmnt =
        container_of(fnode, struct flat_mount, root_node);

    spin_lock(&fmnt->lock);

    size_t dir_iter = dir->dir_offset;
    struct stree_node *snode = stree_get_first(&fmnt->lookup_tree);
    if(snode == NULL) {
        spin_unlock(&fmnt->lock);
        return -ENXIO;
    }

    while(dir_iter > 0) {
        snode = stree_get_next(snode);
        if(snode == NULL) {
            spin_unlock(&fmnt->lock);
            return -ENXIO;
        }
        dir_iter--;
    }

    DEBUG_ASSERT(KERNEL_ADDR(snode));

    strncpy(name_buf, snode->key, buf_len);

    spin_unlock(&fmnt->lock);
    return 0;
}

static struct fs_node_ops
flat_node_ops =
{
    .lookup = flat_dir_lookup,

    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
};

static struct fs_file_ops
flat_file_ops =
{
    .dir_begin = flat_dir_iter_begin,
    .dir_next = flat_dir_iter_next,
    .dir_readattr = flat_dir_iter_readattr,
    .dir_readname = flat_dir_iter_readname,

    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .flush = fs_file_cannot_flush,
    .seek = fs_file_cannot_seek,
};

struct flat_mount *
flat_mount_create(void)
{
    struct flat_mount *mnt =
        kmalloc(sizeof(struct flat_mount));
    if(mnt == NULL) {
        return NULL;
    }
    memset(mnt, 0, sizeof(struct flat_mount));

    spinlock_init(&mnt->lock);
    stree_init(&mnt->lookup_tree);
    ptree_init(&mnt->inode_tree);
    mnt->num_nodes = 0;

    mnt->root_node.fs_node.mount = &mnt->fs_mount;
    mnt->root_node.fs_node.node_ops = &flat_node_ops;
    mnt->root_node.fs_node.file_ops = &flat_file_ops;

    ptree_insert(&mnt->inode_tree, &mnt->root_node.inode_node, 0);

    init_fs_mount_struct(&mnt->fs_mount, &flat_mount_ops);

    return mnt;
}

int
flat_mount_destroy(
        struct flat_mount *mnt)
{
    return -EUNIMPL;
}

int
flat_mount_insert_node(
        struct flat_mount *mnt,
        struct flat_node *node,
        const char *name)
{
    int res;

    char *dup = kstrdup(name);
    if(dup == NULL) {
        return -ENOMEM;
    }
    node->lookup_node.key = dup;

    spin_lock(&mnt->lock);

    res = stree_insert(
            &mnt->lookup_tree,
            &node->lookup_node);
    if(res) {
        spin_unlock(&mnt->lock);
        kfree(dup);
        return res;
    }

    res = ptree_insert_any(
            &mnt->inode_tree,
            &node->inode_node);
    if(res) {
        stree_remove(&mnt->lookup_tree, node->lookup_node.key);
        spin_unlock(&mnt->lock);
        kfree(dup);
        return res;
    }

    node->fs_node.mount = &mnt->fs_mount;
    mnt->num_nodes++;

    DEBUG_ASSERT(mnt->num_nodes > 0);

    spin_unlock(&mnt->lock);
    return 0;
}

int
flat_mount_remove_node(
        struct flat_mount *mnt,
        struct flat_node *node)
{
    int res;
    spin_lock(&mnt->lock);

    DEBUG_ASSERT(mnt->num_nodes > 0);

    struct stree_node *srem =
        stree_remove(&mnt->lookup_tree, node->lookup_node.key);
    DEBUG_ASSERT(srem == &node->lookup_node);

    kfree((void*)srem->key);

    struct ptree_node *prem =
        ptree_remove(&mnt->inode_tree, node->inode_node.key);
    DEBUG_ASSERT(prem == &node->inode_node);

    mnt->num_nodes--;

    spin_unlock(&mnt->lock);
    return 0;
}

struct flat_node *
flat_mount_get_node(
        struct flat_mount *mnt,
        const char *name)
{
    spin_lock(&mnt->lock);
    struct stree_node *snode =
        stree_get(&mnt->lookup_tree, name);
    if(snode == NULL) {
        spin_unlock(&mnt->lock);
        return NULL;
    }
    struct flat_node *node =
        container_of(snode, struct flat_node, lookup_node);
    spin_unlock(&mnt->lock);
    return node;
}

