
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
    void *priv_state;

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

struct kinfo_printer_state {
    void *buffer;
    size_t buflen;
    size_t amount_copied;
    size_t to_skip;
};

static void
kinfo_read_printer(
        struct kinfo_printer_state *state,
        const char *fmt,
        ...)
{
    if(state->amount_copied >= state->buflen) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    size_t copied = state->buflen - state->amount_copied;
    ssize_t attempted = vswprintk(
            state->buffer + state->amount_copied,
            state->to_skip,
            &copied,
            fmt,
            &args);

    va_end(args);

    if(state->to_skip >= attempted) {
        state->to_skip -= attempted;
    } else {
        state->to_skip = 0;
    }

    state->amount_copied += copied;

    return;
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

    struct kinfo_printer_state state = {
        .buflen = amount,
        .buffer = buffer,
        .amount_copied = 0,
        .to_skip = offset,
    };

    (*info->callback)(
            kinfo_read_printer,
            &state,
            info->priv_state);

    return state.amount_copied;

//    kinfo_tree_lock_acquire();
//
//    struct ptree_node *node = ptree_get_max_less_or_eq(&kinfo_tree, offset);
//    if(node == NULL)
//    {
//        kinfo_tree_lock_release();
//        fs_path_put(path);
//        return 0;
//    }
//
//    struct kinfo_frame *frame = container_of(node, struct kinfo_frame, tree_node);
//
//    size_t rel_offset = offset - frame->tree_node.key;
//    size_t room_left = frame->filled_len - rel_offset;
//
//    if(room_left < amount)
//    {
//        amount = room_left;
//    }
//
//    memcpy(buffer, frame->data + rel_offset, amount);
//
//    kinfo_tree_lock_release();

    fs_path_put(path);

    return amount;
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
        kinfo_callback_f *callback,
        void *state)
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
    info->priv_state = state;

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

