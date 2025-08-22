
#include <kanawha/kbd.h>
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

static DECLARE_STREE(kbd_tree);
DEFINE_LOCAL_THREAD_LOCK(kbd_tree_lock);

static struct vfs_mount *kbd_fs_mount = NULL;
static struct fs_node_ops kbd_fs_node_ops;
static struct fs_file_ops kbd_fs_file_ops;

int
kbd_init_struct(
        struct kbd *kbd)
{
    int res;

    for(size_t bit = 0; bit < KBD_NUM_KEYS; bit++) {
        bitmap_clear(kbd->pressed_bitmap, bit);
    }

    kbd->buf_head = 0;
    kbd->buf_tail = 0;

    if(kbd->read_queue == NULL) {
        kbd->read_queue = kmalloc(sizeof(struct waitqueue), KM_KERNEL);
        if(kbd->read_queue == NULL) {
            return -ENOMEM;
        }
        res = waitqueue_init(kbd->read_queue);
        if(res) {
            kfree(kbd->read_queue);
            kbd->read_queue = NULL;
            return res;
        }
	waitqueue_name(kbd->read_queue, "unnamed-kbd");
    }

    return 0;
}

int
kbd_deinit_struct(
        struct kbd *kbd)
{
    if(kbd->read_queue != NULL) {
        waitqueue_disable(kbd->read_queue);
        wake_all(kbd->read_queue);
        waitqueue_deinit(kbd->read_queue);
        kfree(kbd->read_queue);
    }
    return 0;
}

int
register_kbd(
        struct kbd *kbd,
        const char *name)
{
    int res;

    // Can lose buffered events if
    // kbd_init_struct was called before
    // (should be fine)
    res = kbd_init_struct(kbd);
    if(res) {
        return res;
    }
    waitqueue_name(kbd->read_queue, name);

    kbd->global_node.key = name;

    kbd_tree_lock_acquire();

    res = stree_insert(&kbd_tree, &kbd->global_node);
    if(res) {
        kbd_tree_lock_release();
        return res;
    }

    kbd->vfs_node.fs_file_ops = &kbd_fs_file_ops;
    kbd->vfs_node.fs_node_ops = &kbd_fs_node_ops;

    // Assign the node a fs_node index
    if(kbd_fs_mount != NULL) {
        res = vfs_mount_insert_node_and_link_root(
                kbd_fs_mount,
                &kbd->vfs_node,
                name);
        if(res) {
            stree_remove(&kbd_tree, name);
            kbd_tree_lock_release();
            return res;
        }
    }

    kbd_tree_lock_release();

    return 0;
}

int
unregister_kbd(struct kbd *kbd)
{
    return -EUNIMPL;
}

int
kbd_enqueue_event(
        struct kbd *kbd,
        struct kbd_event *event)
{
    if(((kbd->buf_head+1)%KBD_EVENT_BUFLEN) == kbd->buf_tail) {

        // We filled up the buffer, so we are going to dequeue
        // and lose the oldest key event (updates the bitmap)
        struct kbd_event lost;
        kbd_dequeue_event(kbd, &lost);

        wprintk("Lost Key Event: (%s, %s)\n",
                kbd_key_to_string(lost.key),
                kbd_motion_to_string(lost.motion));
    }

    kbd->buffer[kbd->buf_head] = *event;
    kbd->buf_head = ((kbd->buf_head+1)%KBD_EVENT_BUFLEN);

    if(kbd->read_queue) {
        dprintk("kbd_enqueue: (WAKING ALL)\n");
        wake_all(kbd->read_queue);
    }

    return 0;
}

int
kbd_dequeue_event(
        struct kbd *kbd,
        struct kbd_event *event)
{
    if(kbd->buf_head == kbd->buf_tail) {
        return -ENXIO;
    }

    *event = kbd->buffer[kbd->buf_tail];
    kbd->buf_tail = ((kbd->buf_tail+1)%KBD_EVENT_BUFLEN);

    return 0;
}

const char *
kbd_key_to_string(
    kbd_key_t key)
{
    switch(key) {
#define KBD_KEY_TO_STRING_CASE(__KEY)\
        case KBD_ ## __KEY:\
            return #__KEY;

KBD_KEY_XLIST(KBD_KEY_TO_STRING_CASE)

#undef KBD_KEY_TO_STRING_CASE
        case KBD_KEY_UNKNOWN:
            return "UNKNOWN";
        default:
            return "INVALID-KEY";
    }
}

const char *
kbd_motion_to_string(
    kbd_motion_t motion)
{
    switch(motion) {
#define KBD_MOTION_TO_STRING_CASE(__MOTION)\
        case KBD_ ## __MOTION:\
            return #__MOTION;

KBD_MOTION_XLIST(KBD_MOTION_TO_STRING_CASE)

#undef KBD_MOTION_TO_STRING_CASE
        default:
            return "INVALID-MOTION";
    }
}

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

    kbd_tree_lock_acquire();

    kbd_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&kbd_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct kbd *kbd =
            container_of(node, struct kbd, global_node);
        res = vfs_mount_insert_node_and_link_root(
                mnt,
                &kbd->vfs_node,
                node->key);
        if(res) {
            kbd_tree_lock_release();
            return res;
        }
    }
    kbd_tree_lock_release();

    res = sysfs_register_mount(&kbd_fs_mount->fs_mount, "kbd");
    if(res) {
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
    struct kbd *kbd = container_of(vfs_node, struct kbd, vfs_node);

    struct kbd_event event;
    size_t max_events = amount / sizeof(struct kbd_event);
    size_t num_events_written = 0;

    int res;
    struct kbd_event *event_buf = (struct kbd_event*)buffer;

    while(num_events_written < max_events)
    {
        res = kbd_dequeue_event(
            kbd, &event);
        if(res == -ENXIO 
        && num_events_written <= 0
        && kbd->read_queue)
        {
            if(flags & FS_FILE_READ_NON_BLOCKING) {
                // Do not block/wait on the queue for more input
                break;
            }
            dprintk("kbd_read: (SLEEPING)\n");
            res = wait_on(kbd->read_queue);
	    if(res) {
		return res;
	    }
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

static struct fs_node_ops
kbd_fs_node_ops =
{
    // ...
};
FS_NODE_OPS_INIT_UNDEF(kbd_fs_node_ops);

static struct fs_file_ops
kbd_fs_file_ops = {
    .read = kbd_fs_file_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
};
FS_FILE_OPS_INIT_UNDEF(kbd_fs_file_ops);

