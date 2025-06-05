
#include <kanawha/fs/path.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/proc/process.h>
#include <kanawha/list.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/pipe.h>
#include <kanawha/irq.h>
#include <kanawha/lock.h>

#define FS_PATH_MAX_NAMELEN 256

// Global Lock (Not ideal but removing this will probably require RCU)
static DECLARE_ILIST(root_fs_path_list);
DEFINE_LOCAL_IRQ_LOCK(fs_path_global_lock);

struct fs_path
{
    char *name;

    struct fs_node *fs_node;
    ilist_node_t fs_node_node;

    unsigned long refs;

    enum {
        FS_PATH_NODE,
        FS_PATH_MOUNT,
    } type;

    unsigned long flags;

    struct fs_path *parent;
    ilist_t children;
    ilist_node_t child_node;
};

static int
assign_fs_node_to_fs_path(
        struct fs_node *node,
        struct fs_path *path)
{
    int res;
    res = fs_node_get(node);
    if(res) {
        return res;
    }
    fs_node_path_lock_acquire(node);
    ilist_push_tail(&node->path_list, &path->fs_node_node);
    path->fs_node = node;
    fs_node_path_lock_release(node);
    return 0;
}

struct fs_node *
fs_path_get_fs_node(
        struct fs_path *path)
{
    return path->fs_node;
}

const char *
fs_path_get_name(
        struct fs_path *path)
{
    return path->name;
}

struct fs_path *
fs_path_get_parent(
        struct fs_path *path)
{
    int res;

    if(path->parent == NULL) {
        return NULL;
    }

    res = fs_path_get(path->parent);
    if(res) {
        return NULL;
    }

    return path->parent;
}

static int
__fs_path_put(struct fs_path *path);
static int
__fs_path_get(struct fs_path *path);

static int
__fs_path_traverse(
        struct process *process,
        struct fs_path *dir,
        const char *child_name,
        struct fs_path **out)
{
    int res;

    fs_path_global_lock_acquire();

    dprintk("fs_path_traverse(%s -> %s)\n",
            dir->name != NULL ? dir->name : "NULL",
            child_name != NULL ? child_name : "NULL");

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
            fs_path_global_lock_release();
            *out = child;
            return 0;
        }
    }

    // Check for special cases like .. and .
    if(strcmp(child_name, ".") == 0) {
        dir->refs++;
        *out = dir;
        fs_path_global_lock_release();
        return 0;
    } else if(strcmp(child_name, "..") == 0
          && dir != process->root_directory
          && dir->parent != NULL)
    {
        dir->parent->refs++;
        *out = dir->parent;
        fs_path_global_lock_release();
        return 0;
    }

    // Load the file from underlying fs_node
    struct fs_node *dir_fs_node = dir->fs_node;

    size_t mount_index;
    res = fs_node_lookup(
            dir_fs_node,
            child_name,
            &mount_index);
    if(res) {
        // Not a special case, the file just doesn't exist or an error occurred
        dprintk("fs_node_lookup: %s returned (%s)\n",
                child_name, errnostr(res));
        fs_path_global_lock_release();
        return res;
    }

    DEBUG_ASSERT(KERNEL_ADDR(dir_fs_node->mount));
    dprintk("fs_node_lookup -> %p\n", mount_index);

    struct fs_node *child_fs_node =
        fs_mount_get_node(
                dir_fs_node->mount,
                mount_index);
    if(child_fs_node == NULL) {
        fs_path_global_lock_release();
        eprintk("fs_mount_get_node(0x%llx) returned NULL!\n",
                (ull_t)mount_index);
        return -EINVAL;
    }

    struct fs_path *child = kmalloc(sizeof(struct fs_path));
    if(child == NULL) {
        fs_node_put(child_fs_node);
        fs_path_global_lock_release();
        return -ENOMEM;
    }
    memset(child, 0, sizeof(struct fs_path));

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    child->__checksum = FS_PATH_CHECKSUM;
#endif

    child->refs = 1;
    child->name = kstrdup(child_name);
    if(child->name == NULL) {
        kfree(child);
        fs_path_global_lock_release();
        return -ENOMEM;
    }

    res = assign_fs_node_to_fs_path(child_fs_node, child);
    if(res) {
        wprintk("assign_fs_node_to_fs_path returned %s during __fs_path_traverse!\n",
                errnostr(res));
        fs_node_put(child_fs_node);
        kfree(child->name);
        kfree(child);
        fs_path_global_lock_release();
        return res;
    }

    // assign_fs_node_to_fs_path should have gotten a reference to the node
    fs_node_put(child_fs_node);

    res = __fs_path_get(dir);
    DEBUG_ASSERT(res == 0);
    child->parent = dir;
    ilist_push_tail(&dir->children, &child->child_node);
    ilist_init(&child->children);

    *out = child;
    fs_path_global_lock_release();
    return 0;
}

static int
__fs_path_get(struct fs_path *path)
{
    int res;
    DEBUG_ASSERT(KERNEL_ADDR(path->name));
    if(path->refs > 0) {
        path->refs++;
        res = 0;
        dprintk("fs_path_get(%s)\n", path->name);
    } else {
        res = -EINVAL;
        dprintk("fs_path_get(%s) FAILED\n", path->name);
    }
    return res;
}

int
fs_path_get(struct fs_path *path) {
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

    path->refs--;
    dprintk("fs_path_put(%s)\n", path->name);
    if(path->refs > 0) {
        return 0;
    }

    DEBUG_ASSERT(path->refs == 0);
    DEBUG_ASSERT(ilist_empty(&path->children));

    struct fs_path *parent;
    parent = path->parent;
    if(path->parent != NULL) {
        ilist_remove(&path->parent->children, &path->child_node);
        path->parent = NULL;
    } else {
        ilist_remove(&root_fs_path_list, &path->child_node);
    }

    fs_node_path_lock_acquire(path->fs_node);
    ilist_remove(&path->fs_node->path_list, &path->fs_node_node);
    fs_node_path_lock_release(path->fs_node);

    fs_node_put(path->fs_node);
    if(path->name) {
        kfree(path->name);
    }
    kfree(path);

    if(parent == NULL) {
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
fs_path_create_anon_pipe(
        struct fs_path **out)
{
    int res;

    struct fs_path *pipe =
        kmalloc(sizeof(struct fs_path));
    if(pipe == NULL) {
        return -ENOMEM;
    }
    memset(pipe, 0, sizeof(struct fs_path));

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    pipe->__checksum = FS_PATH_CHECKSUM;
#endif

    struct fs_node *fs_node = pipe_fs_get_anon_pipe();
    if(fs_node == NULL) {
        wprintk("fs_path_create_anon_pipe: Failed to create pipefs node!\n");
        kfree(pipe);
        return -EINVAL;
    }

    res = assign_fs_node_to_fs_path(fs_node, pipe);
    if(res) {
        wprintk("assign_fs_node_to_fs_path returned %s during fs_path_create_anon_pipe!\n",
                errnostr(res));
        fs_node_put(fs_node);
        kfree(pipe);
        return res;
    }

    fs_node_put(fs_node);

    pipe->type = FS_PATH_NODE;
    pipe->parent = NULL;

    char buffer[128];
    snprintk(buffer, 128, "pipe-%ld", pipe->fs_node->cache_node.key);
    buffer[127] = '\0';
    pipe->name = kstrdup(buffer);
    pipe->refs = 1; 
    ilist_init(&pipe->children);

    // Add the pipe to the root fs_path list
    fs_path_global_lock_acquire();
    ilist_push_tail(&root_fs_path_list, &pipe->child_node);
    fs_path_global_lock_release();

    *out = pipe;
    return 0;
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

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    mntpoint->__checksum = FS_PATH_CHECKSUM;
#endif

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_root: root_index=%p\n",root_index);

    struct fs_node *fs_node = fs_mount_get_node(mnt, root_index);
    if(fs_node == NULL) {
        kfree(mntpoint);
        return res;
    }

    res = assign_fs_node_to_fs_path(fs_node, mntpoint);
    if(res) {
        wprintk("assign_fs_node_to_fs_path returned %s during fs_path_mount_root!\n",
                errnostr(res));
        fs_node_put(fs_node);
        kfree(mntpoint);
        return res;
    }

    fs_node_put(fs_node);

    mntpoint->type = FS_PATH_MOUNT;
    mntpoint->parent = NULL;
    mntpoint->name = kstrdup("/");
    mntpoint->refs = 1; 
    ilist_init(&mntpoint->children);

    fs_path_global_lock_acquire();
    ilist_push_tail(&root_fs_path_list, &mntpoint->child_node);
    fs_path_global_lock_release();

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

#ifdef CONFIG_DEBUG_CHECKSUM_FS_PATH
    mntpoint->__checksum = FS_PATH_CHECKSUM;
#endif

    size_t root_index;
    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        kfree(mntpoint);
        return res;
    }

    dprintk("fs_path_mount_dir: root_index=%p\n",root_index);

    struct fs_node *fs_node = fs_mount_get_node(mnt, root_index);
    if(fs_node == NULL) {
        eprintk("fs_path_mount_dir: failed to get root node!\n");
        kfree(mntpoint);
        return res;
    }

    res = assign_fs_node_to_fs_path(fs_node, mntpoint);
    if(res) {
        wprintk("assign_fs_node_to_fs_path returned %s during fs_path_mount_dir!\n",
                errnostr(res));
        fs_node_put(fs_node);
        kfree(mntpoint);
        return res;
    }

    fs_node_put(fs_node);

    mntpoint->type = FS_PATH_MOUNT;
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

    fs_path_global_lock_acquire();
    ilist_push_tail(&parent->children, &mntpoint->child_node);
    fs_path_global_lock_release();

    *out = mntpoint;

    return 0;
}

int
fs_path_unmount(
        struct fs_path *mnt_point)
{
    fs_path_global_lock_acquire();

    // Can't unmount if there are any open "fs_path"
    // to children of this node
    if(mnt_point->refs > 1) {
        fs_path_global_lock_release();
        return -EBUSY;
    }

    mnt_point->refs--;
    __fs_path_put(mnt_point);

    fs_path_global_lock_release();
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

    dprintk("fs_path_lookup_for_process(pid=%ld, %s, root=%p, pwd=%p)\n",
            (sl_t)process->id,
            path_str,
            process->root_directory,
            process->working_directory);

    char *dup = kstrdup(path_str);
    if(dup == NULL) {
        return -ENOMEM;
    }

    size_t pathlen = strlen(dup);

    // Treat "" as the current directory
    struct fs_path *cur;
    if(pathlen == 0) {
        cur = process->working_directory;
    }
    else {
      for(size_t i = 0; i < pathlen; i++) {
          if(dup[i] == '/') {
              dup[i] = '\0';
          }
      }

      if(strlen(dup) == 0) {
          // "/..."
          dprintk("fs_path_lookup_for_process(pid=%ld, %s) Starting from root directory (%s)\n",
                  (sl_t)process->id,
                  path_str,
                  process->root_directory->name != NULL ? process->root_directory->name : "NULL");
          cur = process->root_directory;
      } else {
          // "..."
          dprintk("fs_path_lookup_for_process(pid=%ld, %s) Starting from working directory (%s)\n",
                  (sl_t)process->id,
                  path_str,
                  process->root_directory->name != NULL ? process->root_directory->name : "NULL");
          cur = process->working_directory;
      }

      DEBUG_ASSERT(KERNEL_ADDR(cur));

      res = fs_path_get(cur);
      if(res) {
          eprintk("fs_path_lookup_for_process: fs_path_get failed for initial directory! (err=%s)\n",
                  errnostr(res));
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

          res = __fs_path_traverse(process, cur, iter, &next); 
          if(res) {
              fs_path_put(cur);
              dprintk("fs_path_lookup_for_process(pid=%ld, %s) __fs_path_traverse(%p, %s) returned %s\n",
                  (sl_t)process->id,
                  path_str,
                  cur,
                  iter,
                  errnostr(res));
              goto exit;
          }
          
          if(next == NULL) {
              fs_path_put(cur);
              dprintk("fs_path_lookup_for_process(pid=%ld, %s) next node after traversal is NULL!\n",
                  (sl_t)process->id,
                  path_str);
              res = -ENXIO;
              goto exit;
          }

          cur = next;

          // Go to the next path_str
          iter += (curlen+1);
      }
    }

    // TODO: Check process file access permissions here

    *out = cur;
    res = 0;

exit:
    kfree(dup);
    if(res) {
        dprintk("fs_path_lookup_for_process(pid=%ld, %s) Returning %s\n",
                (sl_t)process->id,
                path_str,
                errnostr(res));
    }
    return res;
}

int
dump_fs_paths(
        printk_f *printer)
{
#define PRINT(fmt, ...) \
    do {\
        (*printer)(fmt, __VA_ARGS__);\
    } while(0)

    int res;
    fs_path_global_lock_acquire();

    ilist_node_t *list_node;
    ilist_for_each(list_node, &root_fs_path_list) {
        struct fs_path *path = container_of(list_node, struct fs_path, child_node);
        PRINT("%s\n", path->name);
    }

    fs_path_global_lock_release();
    return 0;

#undef PRINT
}

