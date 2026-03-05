
#include <kanawha/fs/type.h>
#include <kanawha/lock.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>

static DECLARE_STREE(fs_type_tree);
DEFINE_LOCAL_THREAD_LOCK(fs_type_tree_lock);

int
register_fs_type(struct fs_type *type, char *name)
{
    int res;
    type->fs_type_node.key = name;
    fs_type_tree_lock_acquire();
    res = stree_insert(&fs_type_tree, &type->fs_type_node);
    fs_type_tree_lock_release();
    return res;
}

struct fs_type *
fs_type_find(const char *name)
{
    fs_type_tree_lock_acquire();
    struct stree_node *node = stree_get(&fs_type_tree, name);
    fs_type_tree_lock_release();
    if(node == NULL)
    {
        return NULL;
    }
    return container_of(node, struct fs_type, fs_type_node);
}

int
fs_type_cannot_mount_file(struct fs_type *type,
                          struct fs_node *node,
                          struct fs_mount **out)
{
    return -EINVAL;
}

int
fs_type_cannot_mount_special(struct fs_type *type,
                             const char *id,
                             struct fs_mount **out)
{
    return -EINVAL;
}
