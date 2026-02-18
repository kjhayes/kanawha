
#include <kanawha/dev/input.h>
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

struct input_dev_fs_node
{
    struct input_dev *dev;
    struct vfs_node vfs_node;
};

static struct vfs_mount *input_dev_fs_mount = NULL;
static struct fs_node_ops input_dev_fs_node_ops;
static struct fs_file_ops input_dev_fs_file_ops;

static int
input_dev_fs_probe_input_dev(
        struct input_dev *dev
        )
{
    return 0;
}

static int
input_dev_fs_receive_input_dev(
        struct input_dev *dev
        )
{
    int res;

    struct input_dev_fs_node *node = kmalloc(sizeof(*node), KM_KERNEL);
    if(node == NULL) {
        return -ENOMEM;
    }
    node->dev = dev;

    node->vfs_node.fs_node_ops = &input_dev_fs_node_ops;
    node->vfs_node.fs_file_ops = &input_dev_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(
            input_dev_fs_mount,
            &node->vfs_node,
            input_dev_get_name(dev));
    if(res) {
        kfree(node);
        return res;
    }

    return 0;
}

static int
input_dev_fs_revoke_input_dev(
        struct input_dev *dev
        )
{
    wprintk("input_dev_fs_on_unregister is undefined!\n");
    return -EUNIMPL;
}

static struct input_dev_owner
input_dev_fs_owner = {
    .probe = input_dev_fs_probe_input_dev,
    .receive = input_dev_fs_receive_input_dev,
    .revoke = input_dev_fs_revoke_input_dev,
};

static int
input_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create vfs mount!\n");
        return -ENOMEM;
    }

    input_dev_fs_mount = mnt;

    res = register_input_dev_owner(&input_dev_fs_owner);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&input_dev_fs_mount->fs_mount, "input");
    if(res) {
        unregister_input_dev_owner(&input_dev_fs_owner);
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, input_init_fs_mount, "Registering input Sysfs Mount");

static ssize_t 
input_fs_file_read(
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
    struct input_dev_fs_node *kbfs = container_of(vfs_node, struct input_dev_fs_node, vfs_node);
    struct input_dev *input = kbfs->dev;

    struct input_event event;
    size_t max_events = amount / sizeof(struct input_event);
    ssize_t num_events_written = 0;

    int res;
    struct input_event *event_buf = (struct input_event*)buffer;

    while(num_events_written < max_events)
    {
        res = input_driver_dequeue_event(
            input, &event);
        if(res == -EWOULDBLOCK
        && num_events_written <= 0)
        {
            if(flags & FS_FILE_READ_NON_BLOCKING) {
                // Do not block/wait on the queue for more input
                break;
            }
	    input_driver_wait_for_event(input);
            continue;
        }
        else if(res) {
            break;
        }

        event_buf[num_events_written] = event;

        num_events_written++;
    }

    amount = num_events_written*sizeof(struct input_event);

    return amount;
}

static int
input_fs_file_poll(
        struct file *file,
        unsigned long in,
	unsigned long *out)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct input_dev_fs_node *kbfs = container_of(vfs_node, struct input_dev_fs_node, vfs_node);
    struct input_dev *input = kbfs->dev;

    *out = 0;

    if(in & POLL_READ_NONBLOCKING) {
        if(!input_driver_event_buffer_empty(input)) {
	    *out |= POLL_READ_NONBLOCKING;
        }
    }

    return 0;
}

static struct fs_node_ops
input_dev_fs_node_ops =
{
    // ...
};
FS_NODE_OPS_INIT_UNDEF(input_dev_fs_node_ops);

static struct fs_file_ops
input_dev_fs_file_ops = {
    .read = input_fs_file_read,
    .poll = input_fs_file_poll,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
};
FS_FILE_OPS_INIT_UNDEF(input_dev_fs_file_ops);

