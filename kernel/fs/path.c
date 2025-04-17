
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

#define FS_PATH_MAX_NAMELEN 256

// Global Lock (Not ideal but removing this will probably require RCU)
static DECLARE_SPINLOCK(fs_path_global_lock);
static DECLARE_ILIST(root_fs_path_list);

static int
__fs_path_traverse(
        struct process *process,
        struct fs_path *dir,
        const char *child_name,
        struct fs_path **out)
{
    int res;

    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);

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
            spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
            *out = child;
            return 0;
        }
    }

    // Check for special cases like .. and .
    if(strcmp(child_name, ".") == 0) {
        dir->refs++;
        *out = dir;
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        return 0;
    } else if(strcmp(child_name, "..") == 0
          && dir != process->root_directory
          && dir->parent != NULL)
    {
        dir->parent->refs++;
        *out = dir->parent;
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
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
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        return res;
    }

    DEBUG_ASSERT(KERNEL_ADDR(dir_fs_node->mount));
    dprintk("fs_node_lookup -> %p\n", mount_index);

    struct fs_node *child_fs_node =
        fs_mount_get_node(
                dir_fs_node->mount,
                mount_index);
    if(child_fs_node == NULL) {
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        eprintk("fs_mount_get_node(0x%llx) returned NULL!\n",
                (ull_t)mount_index);
        return -EINVAL;
    }

    struct fs_path *child = kmalloc(sizeof(struct fs_path));
    if(child == NULL) {
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        return -ENOMEM;
    }
    memset(child, 0, sizeof(struct fs_path));

    child->refs = 1;
    child->name = kstrdup(child_name);
    if(child->name == NULL) {
        kfree(child);
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        return -ENOMEM;
    }
    child->fs_node = child_fs_node;

    child->parent = dir;
    ilist_push_tail(&dir->children, &child->child_node);
    ilist_init(&child->children);

    *out = child;
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
    return 0;
}

int
fs_path_get(struct fs_path *path)
{
    int res;
    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);
    DEBUG_ASSERT(KERNEL_ADDR(path->name));
    if(path->refs > 0) {
        path->refs++;
        res = 0;
        dprintk("fs_path_get(%s)\n", path->name);
    } else {
        res = -EINVAL;
        dprintk("fs_path_get(%s) FAILED\n", path->name);
    }
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
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

    struct fs_path *parent;
    parent = path->parent;
    if(path->parent != NULL) {
        ilist_remove(&path->parent->children, &path->child_node);
        path->parent = NULL;
    } else {
        ilist_remove(&root_fs_path_list, &path->child_node);
    }

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
    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);
    res = __fs_path_put(path);
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
    return res;
}

int
fs_path_create_anon_pipe(
        struct fs_path **out)
{
    struct fs_path *pipe =
        kmalloc(sizeof(struct fs_path));
    if(pipe == NULL) {
        return -ENOMEM;
    }
    memset(pipe, 0, sizeof(struct fs_path));

    pipe->fs_node = pipe_fs_get_anon_pipe();
    if(pipe->fs_node == NULL) {
        kfree(pipe);
        return -EINVAL;
    }

    pipe->type = FS_PATH_NODE;
    pipe->parent = NULL;

    char buffer[128];
    snprintk(buffer, 128, "pipe-%ld", pipe->fs_node->cache_node.key);
    buffer[127] = '\0';
    pipe->name = kstrdup(buffer);
    pipe->refs = 1; 
    ilist_init(&pipe->children);

    // Add the pipe to the root fs_path list
    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);
    ilist_push_tail(&root_fs_path_list, &pipe->child_node);
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);

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

    mntpoint->type = FS_PATH_MOUNT;
    mntpoint->parent = NULL;
    mntpoint->name = kstrdup("/");
    mntpoint->refs = 1; 
    ilist_init(&mntpoint->children);

    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);
    ilist_push_tail(&root_fs_path_list, &mntpoint->child_node);
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);

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

    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);
    ilist_push_tail(&parent->children, &mntpoint->child_node);
    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);

    *out = mntpoint;

    return 0;
}

int
fs_path_unmount(
        struct fs_path *mnt_point)
{
    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);

    // Can't unmount if there are any open "fs_path"
    // to children of this node
    if(mnt_point->refs > 1) {
        spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
        return -EBUSY;
    }

    mnt_point->refs--;
    __fs_path_put(mnt_point);

    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
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
    int irq_flags = spin_lock_irq_save(&fs_path_global_lock);

    ilist_node_t *list_node;
    ilist_for_each(list_node, &root_fs_path_list) {
        struct fs_path *path = container_of(list_node, struct fs_path, child_node);
        PRINT("%s\n", path->name);
    }

    spin_unlock_irq_restore(&fs_path_global_lock, irq_flags);
    return 0;

#undef PRINT
}

