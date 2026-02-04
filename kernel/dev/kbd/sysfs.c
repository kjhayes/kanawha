
#include <kanawha/dev/kbd.h>
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/uapi/poll.h>

#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

struct kbd_dev_fs_node
{
    struct kbd_dev *dev;
    struct vfs_node vfs_node;
};

static struct vfs_mount *kbd_dev_fs_mount = NULL;
static struct fs_node_ops kbd_dev_fs_node_ops;
static struct fs_file_ops kbd_dev_fs_file_ops;

static int
kbd_dev_fs_probe_kbd_dev(
        struct kbd_dev *dev
        )
{
    return 0;
}

static int
kbd_dev_fs_receive_kbd_dev(
        struct kbd_dev *dev
        )
{
    int res;

    struct kbd_dev_fs_node *node = kmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return -ENOMEM;
    }
    node->dev = dev;

    node->vfs_node.fs_node_ops = &kbd_dev_fs_node_ops;
    node->vfs_node.fs_file_ops = &kbd_dev_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(
            kbd_dev_fs_mount,
            &node->vfs_node,
            kbd_dev_get_name(dev));
    if(res) {
        kfree(node);
        return res;
    }

    return 0;
}

static int
kbd_dev_fs_revoke_kbd_dev(
        struct kbd_dev *dev
        )
{
    wprintk("kbd_dev_fs_on_unregister is undefined!\n");
    return -EUNIMPL;
}

static struct kbd_dev_owner
kbd_dev_fs_owner = {
    .probe = kbd_dev_fs_probe_kbd_dev,
    .receive = kbd_dev_fs_receive_kbd_dev,
    .revoke = kbd_dev_fs_revoke_kbd_dev,
};

static int
kbd_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create vfs mount!\n");
        return -ENOMEM;
    }

    kbd_dev_fs_mount = mnt;

    res = register_kbd_dev_owner(&kbd_dev_fs_owner);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&kbd_dev_fs_mount->fs_mount, "kbd");
    if(res) {
        unregister_kbd_dev_owner(&kbd_dev_fs_owner);
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, kbd_init_fs_mount, "Registering kbd Sysfs Mount");

static ssize_t 
kbd_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct kbd_dev_fs_node *kbfs = container_of(vfs_node, struct kbd_dev_fs_node, vfs_node);
    struct kbd_dev *kbd = kbfs->dev;

    struct kbd_event event;
    size_t max_events = amount / sizeof(struct kbd_event);
    ssize_t num_events_written = 0;

    int res;
    struct kbd_event *event_buf = (struct kbd_event*)buffer;

    while(num_events_written < max_events)
    {
        res = kbd_driver_dequeue_event(
            kbd, &event);
        if(res == -EWOULDBLOCK
        && num_events_written <= 0)
        {
            if(flags & FS_FILE_READ_NON_BLOCKING) {
                // Do not block/wait on the queue for more input
                break;
            }
	    kbd_driver_wait_for_event(kbd);
            continue;
        }
        else if(res) {
            break;
        }

        event_buf[num_events_written] = event;

        num_events_written++;
    }

    amount = num_events_written*sizeof(struct kbd_event);

    return amount;
}

static int
kbd_fs_file_poll(
        struct file *file,
        unsigned long in,
	unsigned long *out)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct kbd_dev_fs_node *kbfs = container_of(vfs_node, struct kbd_dev_fs_node, vfs_node);
    struct kbd_dev *kbd = kbfs->dev;

    *out = 0;

    if(in & POLL_READ_NONBLOCKING) {
        if(!kbd_driver_event_buffer_empty(kbd)) {
	    *out |= POLL_READ_NONBLOCKING;
        }
    }

    return 0;
}

static struct fs_node_ops
kbd_dev_fs_node_ops =
{
    // ...
};
FS_NODE_OPS_INIT_UNDEF(kbd_dev_fs_node_ops);

static struct fs_file_ops
kbd_dev_fs_file_ops = {
    .read = kbd_fs_file_read,
    .poll = kbd_fs_file_poll,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
};
FS_FILE_OPS_INIT_UNDEF(kbd_dev_fs_file_ops);

