
#include <kanawha/fs/path.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/process.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

#define FS_PATH_MAX_NAMELEN 256

// Global Lock (Not ideal but removing this will probably require RCU)
static DECLARE_SPINLOCK(fs_path_global_lock);

static int
__fs_path_traverse(
        struct fs_path *dir,
        const char *child_name,
        struct fs_path **out)
{
    int res;

    spin_lock(&fs_path_global_lock);

    // Try and find the child in the fs_path tree
    ilist_node_t *node;
    ilist_for_each(node, &dir->children) {
        struct fs_path *child =
            container_of(node, struct fs_path, child_node);
      
        DEBUG_ASSERT(KERNEL_ADDR(child->name));
        DEBUG_ASSERT(KERNEL_ADDR(child_name));
        if(strcmp(child->name, child_name) == 0) {
            // This is the right node
            child->refs++;
            spin_unlock(&fs_path_global_lock);
            *out = child;
            return 0;
        }
    }

    // Load the file from underlying fs_node's
    struct fs_node *dir_fs_node = dir->fs_node;

    size_t mount_index;
    res = fs_node_lookup(
            dir_fs_node,
            child_name,
            &mount_index);
    if(res) {
        eprintk("fs_node_lookup: %s returned (%s)\n",
                child_name, errnostr(res));
        spin_unlock(&fs_path_global_lock);
        return res;
    }

    DEBUG_ASSERT(KERNEL_ADDR(dir_fs_node->mount));
    dprintk("fs_node_lookup -> %p\n", mount_index);

    struct fs_node *child_fs_node =
        fs_mount_get_node(
                dir_fs_node->mount,
                mount_index);
    if(child_fs_node == NULL) {
        spin_unlock(&fs_path_global_lock);
        eprintk("fs_mount_get_node(0x%llx) returned NULL!\n",
                (ull_t)mount_index);
        return -EINVAL;
    }

    struct fs_path *child = kmalloc(sizeof(struct fs_path));
    if(child == NULL) {
        spin_unlock(&fs_path_global_lock);
        return -ENOMEM;
    }
    memset(child, 0, sizeof(struct fs_path));

    child->refs = 1;
    child->name = kstrdup(child_name);
    if(child->name == NULL) {
        kfree(child);
        spin_unlock(&fs_path_global_lock);
        return -ENOMEM;
    }
    child->fs_node = child_fs_node;

    child->parent = dir;
    ilist_push_tail(&dir->children, &child->child_node);
    ilist_init(&child->children);

    *out = child;
    spin_unlock(&fs_path_global_lock);
    return 0;
}

int
fs_path_get(struct fs_path *path)
{
    spin_lock(&fs_path_global_lock);
    path->refs++;
    spin_unlock(&fs_path_global_lock);
    return 0;
}

static int
__fs_path_put(struct fs_path *path)
{
    path->refs--;
    if(path->refs != 0) {
        return 0;
    }

    struct fs_path *parent;
    parent = path->parent;
    if(path->parent != NULL) {
        ilist_remove(&path->parent->children, &path->child_node);
        path->parent = NULL;
    }

    fs_node_put(path->fs_node);
    if(path->name) {
        kfree(path->name);
    }
    kfree(path);

    if(parent == NULL) {
        return 0;
    }

    return __fs_path_put(parent);
}

int
fs_path_put(struct fs_path *path) {
    int res;
    spin_lock(&fs_path_global_lock);
    res = __fs_path_put(path);
    spin_unlock(&fs_path_global_lock);
    return res;
}

int
fs_path_mount_root(
        struct fs_mount *mnt,
        struct fs_path **out)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(mnt));
    DEBUG_ASSERT(KERNEL_ADDR(out));

    struct fs_path *mntpoint =
        kmalloc(sizeof(struct fs_path));
    if(mntpoint == NULL) {
        return -ENOMEM;
    }
    memset(mntpoint, 0, sizeof(struct fs_path));

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_root: root_index=%p\n",root_index);

    mntpoint->fs_node = fs_mount_get_node(mnt, root_index);
    if(mntpoint->fs_node == NULL) {
        kfree(mntpoint);
        return res;
    }

    mntpoint->flags |= FS_PATH_MOUNT_POINT;
    mntpoint->parent = NULL;
    mntpoint->name = NULL;
    mntpoint->refs = 1; 
    ilist_init(&mntpoint->children);

    *out = mntpoint;

    return 0;
}

int
fs_path_mount_dir(
        struct fs_path *parent,
        const char *name,
        struct fs_mount *mnt,
        struct fs_path **out)
{
    int res;

    struct fs_path *mntpoint =
        kmalloc(sizeof(struct fs_path));
    if(mntpoint == NULL) {
        return -ENOMEM;
    }
    memset(mntpoint, 0, sizeof(struct fs_path));

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_dir: root_index=%p\n",root_index);

    mntpoint->fs_node = fs_mount_get_node(mnt, root_index);
    if(mntpoint->fs_node == NULL) {
        eprintk("fs_path_mount_dir: failed to get root node!\n");
        kfree(mntpoint);
        return res;
    }

    mntpoint->flags |= FS_PATH_MOUNT_POINT;
    mntpoint->parent = NULL;
    mntpoint->name = kstrdup(name);
    if(mntpoint->name == NULL) {
        kfree(mntpoint);
        return -ENOMEM;
    }
    mntpoint->refs = 1; 
    ilist_init(&mntpoint->children);

    fs_path_get(parent);
    mntpoint->parent = parent;

    spin_lock(&fs_path_global_lock);
    ilist_push_tail(&parent->children, &mntpoint->child_node);
    spin_unlock(&fs_path_global_lock);

    *out = mntpoint;

    return 0;
}

int
fs_path_unmount(
        struct fs_path *mnt_point)
{
    spin_lock(&fs_path_global_lock);

    // Can't unmount if there are any open "fs_path"
    // to children of this node
    if(mnt_point->refs > 1) {
        spin_unlock(&fs_path_global_lock);
        return -EBUSY;
    }

    mnt_point->refs--;
    __fs_path_put(mnt_point);

    spin_unlock(&fs_path_global_lock);
    return -EUNIMPL;
}

int
fs_path_lookup_for_process(
        struct process *process,
        const char *path_str,
        unsigned long access_flags,
        unsigned long mode_flags,
        struct fs_path **out)
{
    int res;

    dprintk("fs_path_lookup_for_process(pid=%ld, %s)\n",
            (sl_t)process->id, path_str);

    char *dup = kstrdup(path_str);
    if(dup == NULL) {
        return -ENOMEM;
    }

    size_t pathlen = strlen(dup);
    for(size_t i = 0; i < pathlen; i++) {
        if(dup[i] == '/') {
            dup[i] = '\0';
        }
    }

    struct fs_path *cur = process->root;
    res = fs_path_get(cur);
    if(res) {
        goto exit;
    }

    char *dup_end = dup + pathlen;

    char *iter = dup;
    while(iter < dup_end) {

        // TODO: Check process directory permissions on cur here

        size_t curlen = strlen(iter);

        if(curlen == 0) {
            iter += 1;
            continue;
        }

        struct fs_path *next;
        // Increments the ref counter on "next" on success
        res = __fs_path_traverse(cur, iter, &next);
        if(res) {
            fs_path_put(cur);
            goto exit;
        }

        if(next == NULL) {
            fs_path_put(cur);
            res = -ENXIO;
            goto exit;
        }

        cur = next;

        // Go to the next path_str
        iter += (curlen+1);
    }

    // TODO: Check process file access permissions here

    *out = cur;

    res = 0;
exit:
    kfree(dup);
    return res;
}

