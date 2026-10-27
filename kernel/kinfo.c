
#include <kanawha/kinfo.h>
#include <kanawha/registry.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

static int kinfo_attach_to_mount_lockless(struct kinfo *info);
static int kinfo_remove_from_mount_lockless(struct kinfo *info);

#define KINFO_FLAG_ATTACHED (1UL<<0)
struct kinfo {
    unsigned long flags;
    ilist_node_t list_node;

    kinfo_callback_f *callback;

    struct vfs_node vfs_node;
    char *name;
};

DEFINE_LOCAL_IRQ_LOCK(kinfo_list_lock);
DECLARE_ILIST(kinfo_list);

static struct vfs_mount *kinfo_mount = NULL;
static struct fs_node_ops kinfo_node_ops;
static struct fs_file_ops kinfo_file_ops;

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

struct kinfo_printer {
    char *buffer;
    size_t buflen;
    ssize_t offset;
    size_t amount_copied;
    struct printer printer;
};

static int
kinfo_printer_putc(
        struct printer *p,
        char c)
{
    struct kinfo_printer *kp = container_of(p, struct kinfo_printer, printer);
    if(kp->offset >= 0 && kp->offset < kp->buflen) {
        kp->buffer[kp->offset] = c;
        kp->amount_copied++;
    }
    kp->offset++;
    return 0;
}

static ssize_t
kinfo_fs_file_read(struct file *file,
                  void *buffer,
                  ssize_t amount,
                  unsigned long flags)
{
    int res;

    struct fs_path *path = file->path;
    res = fs_path_get(path);
    if(res)
    {
        return res;
    }

    struct vfs_node *node = vfs_node_from_fs_path(path);
    if(node == NULL) {
        fs_path_put(path);
        return -EINVAL;
    }

    struct kinfo *info = container_of(node, struct kinfo, vfs_node);

    size_t offset = file->seek_offset;

    struct kinfo_printer printer = {
        .buflen = amount,
        .buffer = buffer,
        .amount_copied = 0,
        .offset = -(ssize_t)offset,
        .printer = {
            .putc = kinfo_printer_putc,
            .puts = printer_puts_using_write,
            .write = printer_write_using_putc,
        },
    };

    (*info->callback)(
            info,
            &printer.printer);

    fs_path_put(path);
    return printer.amount_copied;
}

static struct fs_node_ops kinfo_fs_node_ops = {
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(kinfo_fs_node_ops);

static struct fs_file_ops kinfo_fs_file_ops = {
    .read = kinfo_fs_file_read,
    .write = fs_file_cannot_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_any,
};
FS_FILE_OPS_INIT_UNDEF(kinfo_fs_file_ops);

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
    info->name = kstrdup(name);
    if(info->name == NULL) {
        kfree(info);
        return NULL;
    }
    info->flags = 0;

    info->callback = callback;

    kinfo_list_lock_acquire();
    kinfo_attach_to_mount_lockless(info);
    kinfo_list_lock_release();

    return info;
}

int
kinfo_destroy(
        struct kinfo *info)
{
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

    info->vfs_node.fs_node_ops = &kinfo_fs_node_ops;
    info->vfs_node.fs_file_ops = &kinfo_fs_file_ops;
    res = vfs_mount_insert_node_and_link_root(
            kinfo_mount,
            &info->vfs_node,
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
    res = vfs_mount_remove_node(kinfo_mount, &info->vfs_node);
    if(res) {
        return res;
    }
    info->flags &= ~KINFO_FLAG_ATTACHED;
    return 0;
}

