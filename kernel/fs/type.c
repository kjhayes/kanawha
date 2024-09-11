
#include <kanawha/fs/type.h>
#include <kanawha/stree.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(fs_type_tree_lock);
static DECLARE_STREE(fs_type_tree);

int
register_fs_type(
        struct fs_type *type,
        char *name)
{
    type->fs_type_node.key = name;
    return stree_insert(&fs_type_tree, &type->fs_type_node);
}

struct fs_type *
fs_type_find(const char *name)
{
    struct stree_node *node = stree_get(&fs_type_tree, name);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct fs_type, fs_type_node);
}


int
fs_type_cannot_mount_file(
        struct fs_type *type,
        struct fs_node *node,
        struct fs_mount **out)
{
    return -EINVAL;
}

int
fs_type_cannot_mount_special(
        struct fs_type *type,
        const char *id,
        struct fs_mount **out)
{
    return -EINVAL;
}

