
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/fs/type.h>
#include <kanawha/stree.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>

DEFINE_LOCAL_THREAD_LOCK(sysfs_mount_lock);
static DECLARE_STREE(sysfs_mount_tree);

struct sysfs_mount {
    struct fs_mount *mount;
    struct stree_node tree_node;
};

int
sysfs_register_mount(
        struct fs_mount *mnt,
        const char *id)
{
    int res;
    sysfs_mount_lock_acquire();

    struct stree_node *node = stree_get(&sysfs_mount_tree, id);
    if(node != NULL) {
        sysfs_mount_lock_release();
        return -EEXIST;
    }

    struct sysfs_mount *sysmnt = kzmalloc(sizeof(struct sysfs_mount), KM_KERNEL);
    if(sysmnt == NULL) {
        sysfs_mount_lock_release();
        return -ENOMEM;
    }

    sysmnt->mount = mnt;
    sysmnt->tree_node.key = kstrdup(id);
    if(sysmnt->tree_node.key == NULL) {
        kfree(sysmnt);
        sysfs_mount_lock_release();
        return -ENOMEM;
    }

    res = stree_insert(&sysfs_mount_tree, &sysmnt->tree_node);
    if(res) {
        kfree((void*)sysmnt->tree_node.key);
        kfree(sysmnt);
        sysfs_mount_lock_release();
        return res;
    }

    sysfs_mount_lock_release();
    return 0;
}

int
sysfs_unregister_mount(
        const char *id)
{
    int res;
    sysfs_mount_lock_acquire();

    struct stree_node *rem =
        stree_remove(&sysfs_mount_tree, id);

    DEBUG_ASSERT(KERNEL_ADDR(rem));

    struct sysfs_mount *mnt =
        container_of(rem, struct sysfs_mount, tree_node);

    kfree((void*)mnt->tree_node.key);
    kfree(mnt);

    sysfs_mount_lock_release();
    return 0;
}

static int
sysfs_mount_special(
        struct fs_type *type,
        const char *id,
        struct fs_mount **out)
{
    int res;
    sysfs_mount_lock_acquire();

    struct stree_node *snode =
        stree_get(&sysfs_mount_tree, id);
    if(snode == NULL) {
        sysfs_mount_lock_release();
        return -ENXIO;
    }

    struct sysfs_mount *mnt =
        container_of(snode, struct sysfs_mount, tree_node);

    DEBUG_ASSERT(KERNEL_ADDR(mnt->mount));
    *out = mnt->mount;

    sysfs_mount_lock_release();
    return 0;
}

static int
sysfs_unmount(
        struct fs_type *type,
        struct fs_mount *mnt)
{
    return 0;
}

struct fs_mount *
sysfs_mount_find(
        const char *id)
{
    struct fs_mount *mnt;
    sysfs_mount_lock_acquire();
    struct stree_node *snode = stree_get(&sysfs_mount_tree, id);
    if(snode == NULL) {
        mnt = NULL;
    } else {
        struct sysfs_mount *sysfs_mount = container_of(snode, struct sysfs_mount, tree_node);
        mnt = sysfs_mount->mount;
    }
    sysfs_mount_lock_release();
    return mnt;
}

struct fs_type sysfs_fs_type = {
    .mount_file = fs_type_cannot_mount_file,
    .mount_special = sysfs_mount_special,
    .unmount = sysfs_unmount,
};

static int
sysfs_register_fs_type(void)
{
    return register_fs_type(&sysfs_fs_type, "sys");
}
declare_init_desc(fs, sysfs_register_fs_type, "Registering sysfs");

