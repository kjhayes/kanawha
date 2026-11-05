
#include <kanawha/kinfo.h>
#include <kanawha/registry.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/vfs_printer.h>

static int kinfo_attach_to_mount_lockless(struct kinfo *info);
static int kinfo_remove_from_mount_lockless(struct kinfo *info);

#define KINFO_FLAG_ATTACHED (1UL<<0)
struct kinfo {
    unsigned long flags;
    ilist_node_t list_node;

    kinfo_callback_f *callback;

    struct vfs_printer_node vfs_printer_node;

    char *name;
};

DEFINE_LOCAL_IRQ_LOCK(kinfo_list_lock);
DECLARE_ILIST(kinfo_list);

static struct vfs_mount *kinfo_mount = NULL;

static int
kinfo_init_fs_mount(void)
{
    int res;

    kinfo_list_lock_acquire();

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        kinfo_list_lock_release();
        eprintk("Failed to create kinfo vfs mount!\n");
        return -ENOMEM;
    }

    res = sysfs_register_mount(&mnt->fs_mount, "info");
    if(res)
    {
        kinfo_list_lock_release();
        vfs_mount_destroy(mnt);
        return res;
    }

    kinfo_mount = mnt;

    ilist_node_t *iter;
    ilist_for_each(iter, &kinfo_list) {
        struct kinfo *info = container_of(iter, struct kinfo, list_node);

        if(!(info->flags & KINFO_FLAG_ATTACHED)) {
        res = kinfo_attach_to_mount_lockless(info);
            if(res) {
                wprintk("Failed to attach kinfo node \"%s\"!\n",
                        kinfo_get_name(info));
                continue;
            }
        }
    }

    kinfo_list_lock_release();
    return 0;

}
declare_init_desc(fs, kinfo_init_fs_mount, "Registering \"info\" Sysfs Mount");

static int
kinfo_vfs_printer_callback(
        struct vfs_printer_node *printer_node,
        struct printer *printer)
{
    struct kinfo *info =
        container_of(printer_node, struct kinfo, vfs_printer_node);

    (*info->callback)(info, printer);

    return 0;
}

struct kinfo *
kinfo_create(
        const char *name,
        kinfo_callback_f *callback)
{
    int res;

    struct kinfo *info = kzmalloc(sizeof(*info), KM_KERNEL);
    if(info == NULL) {
        return NULL;
    }
    info->name = kstrdup(name, KM_KERNEL);
    if(info->name == NULL) {
        kfree(info);
        return NULL;
    }
    info->flags = 0;
    info->callback = callback;

    res = vfs_init_printer_node(
            &info->vfs_printer_node,
            kinfo_vfs_printer_callback);
    if(res) {
        kfree(info->name);
        kfree(info);
        return NULL;
    }

    kinfo_list_lock_acquire();
    kinfo_attach_to_mount_lockless(info);
    kinfo_list_lock_release();

    return info;
}

int
kinfo_destroy(
        struct kinfo *info)
{
    int res;

    kinfo_list_lock_acquire();
    kinfo_remove_from_mount_lockless(info);
    kinfo_list_lock_release();

    kfree(info->name);
    kfree(info);

    return 0;
}

const char *
kinfo_get_name(
        struct kinfo *info)
{
    return info->name;
}

static int
kinfo_attach_to_mount_lockless(
        struct kinfo *info)
{
    int res;

    if(info->flags & KINFO_FLAG_ATTACHED) {
        return 0;
    }
    if(kinfo_mount == NULL) {
        info->flags &= ~KINFO_FLAG_ATTACHED;
        return 0;
    }

    res = vfs_mount_insert_node_and_link_root(
            kinfo_mount,
            vfs_printer_node_as_vfs_node(&info->vfs_printer_node),
            kinfo_get_name(info));
    if(res) {
        info->flags &= ~KINFO_FLAG_ATTACHED;
        return res;
    }
    info->flags |= KINFO_FLAG_ATTACHED;

    return 0;
}
static int
kinfo_remove_from_mount_lockless(
        struct kinfo *info)
{
    int res;
    if(!(info->flags & KINFO_FLAG_ATTACHED)) {
        return 0;
    }
    if(kinfo_mount == NULL) {
        return -EINVAL;
    }
    res = vfs_mount_remove_node(
            kinfo_mount,
            vfs_printer_node_as_vfs_node(&info->vfs_printer_node));
    if(res) {
        return res;
    }
    info->flags &= ~KINFO_FLAG_ATTACHED;
    return 0;
}

