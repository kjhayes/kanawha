
#include <kanawha/assert.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/path.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/pipe.h>
#include <kanawha/proc/process.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

#define FS_PATH_MAX_NAMELEN 256
#define SYMLINK_BUFLEN 128
#define MAX_SYMLINK_DEPTH 8

// Global Lock (Not ideal but removing this will probably require RCU)
static DECLARE_ILIST(root_fs_path_list);
DEFINE_LOCAL_IRQ_LOCK(fs_path_global_lock);

struct fs_path
{
    char *name;
    unsigned dynamic_name;

    struct fs_node *fs_node;
    ilist_node_t fs_node_node;

    unsigned long refs;

    enum
    {
        FS_PATH_NODE,
        FS_PATH_MOUNT,
    } type;

    unsigned long flags;

    struct fs_path *parent;
    ilist_t children;
    ilist_node_t child_node;
};

static int
assign_fs_node_to_fs_path(struct fs_node *node, struct fs_path *path)
{
    int res;
    res = fs_node_get(node);
    if(res)
    {
        return res;
    }
    path->fs_node = node;
    return 0;
}

struct fs_node *
fs_path_get_fs_node(struct fs_path *path)
{
    return path->fs_node;
}

const char *
fs_path_get_name(struct fs_path *path)
{
    return path->name;
}

struct fs_path *
fs_path_get_parent(struct fs_path *path)
{
    int res;

    if(path->parent == NULL)
    {
        return NULL;
    }

    res = fs_path_get(path->parent);
    if(res)
    {
        return NULL;
    }

    return path->parent;
}

static int
__fs_path_put(struct fs_path *path);
static int
__fs_path_get(struct fs_path *path);

static int
__fs_path_lookup_for_process(struct process *process,
                             struct fs_path *dir_path,
                             const char *path_str,
                             unsigned long access_flags,
                             unsigned long mode_flags,
                             struct fs_path **out,
                             int symlink_depth);

static int
__fs_path_traverse(struct process *process,
                   struct fs_path *dir,
                   const char *child_name,
                   unsigned long access_flags,
                   unsigned long mode_flags,
                   struct fs_path **out,
                   int symlink_depth)
{
    int res;

    char symlink_buffer[SYMLINK_BUFLEN + 1];
    symlink_buffer[SYMLINK_BUFLEN] = '\0';

    fs_path_global_lock_acquire();

    dprintk("__fs_path_traverse(%s -> %s)\n",
            dir->name != NULL ? dir->name : "NULL",
            child_name != NULL ? child_name : "NULL");

    // Try and find the child in the fs_path tree
    ilist_node_t *node;
    ilist_for_each(node, &dir->children)
    {
        struct fs_path *child = container_of(node, struct fs_path, child_node);

        DEBUG_ASSERT(KERNEL_ADDR(child->name));
        DEBUG_ASSERT(KERNEL_ADDR(child_name));
        if(strcmp(child->name, child_name) == 0)
        {
            // This is the right node
            child->refs++;
            fs_path_global_lock_release();
            *out = child;
            return 0;
        }
    }

    // Check for special cases like .. and .
    if(strcmp(child_name, ".") == 0)
    {
        dir->refs++;
        *out = dir;
        fs_path_global_lock_release();
        return 0;
    }
    else if(strcmp(child_name, "..") == 0 && dir != process->root_directory &&
            dir->parent != NULL)
    {
        dir->parent->refs++;
        *out = dir->parent;
        fs_path_global_lock_release();
        return 0;
    }

    // Load the file from underlying fs_node
    struct fs_node *dir_fs_node = dir->fs_node;

    size_t mount_index;
    res = fs_node_lookup(dir_fs_node,
                         child_name,
                         &mount_index,
                         symlink_buffer,
                         SYMLINK_BUFLEN);
    if(res < 0)
    {
        // Not a special case, the file just doesn't exist or an error
        // occurred
        dprintk("fs_node_lookup: %s returned (%s)\n",
                child_name,
                errnostr(res));
        fs_path_global_lock_release();
        return res;
    }

    if(res == FS_NODE_LOOKUP_HARD)
    {
        DEBUG_ASSERT(KERNEL_ADDR(dir_fs_node->mount));
        dprintk("fs_node_lookup -> %p\n", mount_index);

        struct fs_node *child_fs_node =
            fs_mount_get_node(dir_fs_node->mount, mount_index);
        if(child_fs_node == NULL)
        {
            fs_path_global_lock_release();
            eprintk("fs_mount_get_node(0x%llx) returned NULL!\n",
                    (ull_t)mount_index);
            return -EINVAL;
        }

        struct fs_path *child = kzmalloc(sizeof(struct fs_path), KM_KERNEL);
        if(child == NULL)
        {
            fs_node_put(child_fs_node);
            fs_path_global_lock_release();
            return -ENOMEM;
        }

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
        child->__checksum = FS_PATH_CHECKSUM;
#endif

        child->refs = 1;
        child->name = kstrdup(child_name);
        if(child->name == NULL)
        {
            kfree(child);
            fs_path_global_lock_release();
            return -ENOMEM;
        }
        child->dynamic_name = 1;

        res = assign_fs_node_to_fs_path(child_fs_node, child);
        if(res)
        {
            wprintk("assign_fs_node_to_fs_path returned %s during "
                    "__fs_path_traverse!\n",
                    errnostr(res));
            fs_node_put(child_fs_node);
            kfree(child->name);
            kfree(child);
            fs_path_global_lock_release();
            return res;
        }

        // assign_fs_node_to_fs_path should have gotten a reference to the
        // node
        fs_node_put(child_fs_node);

        res = __fs_path_get(dir);
        DEBUG_ASSERT(res == 0);
        child->parent = dir;
        ilist_push_tail(&dir->children, &child->child_node);
        ilist_init(&child->children);

        *out = child;
    }
    else if(res == FS_NODE_LOOKUP_SYMBOLIC)
    {
        struct fs_path *root = process->root_directory;
        fs_path_get(root);
        res = __fs_path_lookup_for_process(process,
                                           root,
                                           symlink_buffer,
                                           access_flags,
                                           mode_flags,
                                           out,
                                           symlink_depth + 1);
        fs_path_put(root);
        if(res)
        {
            fs_path_global_lock_release();
            return res;
        }
    }

    fs_path_global_lock_release();
    return 0;
}

static int
__fs_path_get(struct fs_path *path)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(path->name));
    if(path->refs > 0)
    {
        path->refs++;
        res = 0;
        dprintk("fs_path_get(%s)\n", path->name);
    }
    else
    {
        res = -EINVAL;
        dprintk("fs_path_get(%s) FAILED\n", path->name);
    }
    return res;
}

int
fs_path_get(struct fs_path *path)
{
    int res;
    fs_path_global_lock_acquire();
    res = __fs_path_get(path);
    fs_path_global_lock_release();
    return res;
}

static int
__fs_path_put(struct fs_path *path)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(path));

    path->refs--;
    dprintk("fs_path_put(%s)\n", path->name);
    if(path->refs > 0)
    {
        return 0;
    }

    DEBUG_ASSERT(path->refs == 0);
    DEBUG_ASSERT(ilist_empty(&path->children));

    struct fs_path *parent;
    parent = path->parent;
    if(path->parent != NULL)
    {
        ilist_remove(&path->parent->children, &path->child_node);
        path->parent = NULL;
    }
    else
    {
        ilist_remove(&root_fs_path_list, &path->child_node);
    }

    fs_node_put(path->fs_node);
    if(path->dynamic_name && path->name)
    {
        kfree(path->name);
    }
    kfree(path);

    if(parent == NULL)
    {
        return 0;
    }

    res = __fs_path_put(parent);
    return res;
}

int
fs_path_put(struct fs_path *path)
{
    int res;
    fs_path_global_lock_acquire();
    res = __fs_path_put(path);
    fs_path_global_lock_release();
    return res;
}

int
fs_path_create_anonymous(struct fs_node *fs_node, struct fs_path **out)
{
    int res;

    struct fs_path *path = kzmalloc(sizeof(struct fs_path), KM_KERNEL);
    if(path == NULL)
    {
        return -ENOMEM;
    }

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    path->__checksum = FS_PATH_CHECKSUM;
#endif

    res = assign_fs_node_to_fs_path(fs_node, path);
    if(res)
    {
        wprintk("assign_fs_node_to_fs_path returned %s during "
                "fs_path_create_anonymous!\n",
                errnostr(res));
        kfree(path);
        return res;
    }

    path->type = FS_PATH_NODE;
    path->parent = NULL;

    path->name = "anon";
    path->dynamic_name = 0;
    path->refs = 1;
    ilist_init(&path->children);

    // Add the path to the root fs_path list
    fs_path_global_lock_acquire();
    ilist_push_tail(&root_fs_path_list, &path->child_node);
    fs_path_global_lock_release();

    *out = path;
    return 0;
}

int
fs_path_mount_root(struct fs_mount *mnt, struct fs_path **out)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(mnt));
    DEBUG_ASSERT(KERNEL_ADDR(out));

    struct fs_path *mntpoint = kzmalloc(sizeof(struct fs_path), KM_KERNEL);
    if(mntpoint == NULL)
    {
        return -ENOMEM;
    }

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    mntpoint->__checksum = FS_PATH_CHECKSUM;
#endif

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res)
    {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_root: root_index=%p\n", root_index);

    struct fs_node *fs_node = fs_mount_get_node(mnt, root_index);
    if(fs_node == NULL)
    {
        kfree(mntpoint);
        return res;
    }

    res = assign_fs_node_to_fs_path(fs_node, mntpoint);
    if(res)
    {
        wprintk("assign_fs_node_to_fs_path returned %s during "
                "fs_path_mount_root!\n",
                errnostr(res));
        fs_node_put(fs_node);
        kfree(mntpoint);
        return res;
    }

    fs_node_put(fs_node);

    mntpoint->type = FS_PATH_MOUNT;
    mntpoint->parent = NULL;
    mntpoint->name = "/";
    mntpoint->dynamic_name = 0;
    mntpoint->refs = 1;
    ilist_init(&mntpoint->children);

    fs_path_global_lock_acquire();
    ilist_push_tail(&root_fs_path_list, &mntpoint->child_node);
    fs_path_global_lock_release();

    *out = mntpoint;

    return 0;
}

int
fs_path_mount_dir(struct fs_path *parent,
                  const char *name,
                  struct fs_mount *mnt,
                  struct fs_path **out)
{
    int res;

    struct fs_path *mntpoint = kzmalloc(sizeof(struct fs_path), KM_KERNEL);
    if(mntpoint == NULL)
    {
        return -ENOMEM;
    }

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    mntpoint->__checksum = FS_PATH_CHECKSUM;
#endif

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res)
    {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_dir: root_index=%p\n", root_index);

    struct fs_node *fs_node = fs_mount_get_node(mnt, root_index);
    if(fs_node == NULL)
    {
        eprintk("fs_path_mount_dir: failed to get root node!\n");
        kfree(mntpoint);
        return res;
    }

    res = assign_fs_node_to_fs_path(fs_node, mntpoint);
    if(res)
    {
        wprintk("assign_fs_node_to_fs_path returned %s during "
                "fs_path_mount_dir!\n",
                errnostr(res));
        fs_node_put(fs_node);
        kfree(mntpoint);
        return res;
    }

    fs_node_put(fs_node);

    mntpoint->type = FS_PATH_MOUNT;
    mntpoint->parent = NULL;
    mntpoint->name = kstrdup(name);
    if(mntpoint->name == NULL)
    {
        kfree(mntpoint);
        return -ENOMEM;
    }
    mntpoint->dynamic_name = 1;
    mntpoint->refs = 1;
    ilist_init(&mntpoint->children);

    fs_path_get(parent);
    mntpoint->parent = parent;

    fs_path_global_lock_acquire();
    ilist_push_tail(&parent->children, &mntpoint->child_node);
    fs_path_global_lock_release();

    *out = mntpoint;

    return 0;
}

int
fs_path_unmount(struct fs_path *mnt_point)
{
    fs_path_global_lock_acquire();

    // Can't unmount if there are any open "fs_path"
    // to children of this node
    if(mnt_point->refs > 1)
    {
        fs_path_global_lock_release();
        return -EBUSY;
    }

    mnt_point->refs--;
    __fs_path_put(mnt_point);

    fs_path_global_lock_release();
    return -EUNIMPL;
}

static int
__fs_path_lookup_for_process(struct process *process,
                             struct fs_path *dir_path,
                             const char *path_str,
                             unsigned long access_flags,
                             unsigned long mode_flags,
                             struct fs_path **out,
                             int symlink_depth)
{
    int res;

    if(symlink_depth > MAX_SYMLINK_DEPTH)
    {
        return -ELOOP;
    }

    dprintk("fs_path_lookup_for_process(pid=%ld, %s, root=%p, pwd=%p)\n",
            (sl_t)process->id,
            path_str,
            process->root_directory,
            process->working_directory);

    char *dup = kstrdup(path_str);
    if(dup == NULL)
    {
        return -ENOMEM;
    }

    size_t pathlen = strlen(dup);

    // Treat "" as the current directory
    struct fs_path *cur = dir_path;

    for(size_t i = 0; i < pathlen; i++)
    {
        if(dup[i] == '/')
        {
            dup[i] = '\0';
        }
    }

    DEBUG_ASSERT(KERNEL_ADDR(cur));

    res = fs_path_get(cur);
    if(res)
    {
        eprintk("fs_path_lookup_for_process: fs_path_get failed for initial "
                "directory! (err=%s)\n",
                errnostr(res));
        goto exit;
    }

    char *dup_end = dup + pathlen;

    char *iter = dup;
    while(iter < dup_end)
    {

        // TODO: Check process directory permissions on cur here

        size_t curlen = strlen(iter);

        if(curlen == 0)
        {
            iter += 1;
            continue;
        }

        struct fs_path *next;

        res = __fs_path_traverse(process,
                                 cur,
                                 iter,
                                 access_flags,
                                 mode_flags,
                                 &next,
                                 symlink_depth);
        if(res)
        {
            fs_path_put(cur);
            dprintk("fs_path_lookup_for_process(pid=%ld, %s) "
                    "__fs_path_traverse(%p, %s) returned %s\n",
                    (sl_t)process->id,
                    path_str,
                    cur,
                    iter,
                    errnostr(res));
            goto exit;
        }

        if(next == NULL)
        {
            fs_path_put(cur);
            dprintk("fs_path_lookup_for_process(pid=%ld, %s) next "
                    "node after "
                    "traversal is NULL!\n",
                    (sl_t)process->id,
                    path_str);
            res = -ENXIO;
            goto exit;
        }

        cur = next;

        // Go to the next path_str
        iter += (curlen + 1);
    }

    // TODO: Check process file access permissions here

    *out = cur;
    res = 0;

exit:
    kfree(dup);
    if(res)
    {
        dprintk("fs_path_lookup_for_process(pid=%ld, %s) Returning %s\n",
                (sl_t)process->id,
                path_str,
                errnostr(res));
    }
    return res;
}

int
fs_path_lookup_for_process(struct process *process,
                           struct fs_path *dir_path,
                           const char *path_str,
                           unsigned long access_flags,
                           unsigned long mode_flags,
                           struct fs_path **out)
{
    return __fs_path_lookup_for_process(process,
                                        dir_path,
                                        path_str,
                                        access_flags,
                                        mode_flags,
                                        out,
                                        0);
}

int
dump_fs_paths(printk_f *printer)
{
#define PRINT(fmt, ...)                                                        \
    do                                                                         \
    {                                                                          \
        (*printer)(fmt, __VA_ARGS__);                                          \
    } while(0)

    int res;
    fs_path_global_lock_acquire();

    ilist_node_t *list_node;
    ilist_for_each(list_node, &root_fs_path_list)
    {
        struct fs_path *path =
            container_of(list_node, struct fs_path, child_node);
        PRINT("%s\n", path->name);
    }

    fs_path_global_lock_release();
    return 0;

#undef PRINT
}
