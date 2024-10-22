
#include <kanawha/kbd.h>
#include <kanawha/errno.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/flat.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>

static DECLARE_SPINLOCK(kbd_tree_lock);
static DECLARE_STREE(kbd_tree);

static struct flat_mount *kbd_fs_mount = NULL;
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
        kbd->read_queue = kmalloc(sizeof(struct waitqueue));
        if(kbd->read_queue == NULL) {
            return -ENOMEM;
        }
        res = waitqueue_init(kbd->read_queue);
        if(res) {
            kfree(kbd->read_queue);
            kbd->read_queue = NULL;
            return res;
        }
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

    kbd->global_node.key = name;

    spin_lock(&kbd_tree_lock);

    res = stree_insert(&kbd_tree, &kbd->global_node);
    if(res) {
        spin_unlock(&kbd_tree_lock);
        return res;
    }

    kbd->flat_fs_node.fs_node.file_ops = &kbd_fs_file_ops;
    kbd->flat_fs_node.fs_node.node_ops = &kbd_fs_node_ops;
    kbd->flat_fs_node.fs_node.unload = NULL;


    // Assign the node a fs_node index
    if(kbd_fs_mount != NULL) {
        res = flat_mount_insert_node(
                kbd_fs_mount,
                &kbd->flat_fs_node,
                name);
        if(res) {
            stree_remove(&kbd_tree, name);
            spin_unlock(&kbd_tree_lock);
            return res;
        }
    }

    spin_unlock(&kbd_tree_lock);

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

        dprintk("Lost Key Event: (%s, %s)\n",
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

    struct flat_mount *mnt;
    mnt = flat_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create flat mount!\n");
        return -ENOMEM;
    }

    spin_lock(&kbd_tree_lock);

    kbd_fs_mount = mnt;

    struct stree_node *node = stree_get_first(&kbd_tree);
    for(; node != NULL; node = stree_get_next(node)) {
        struct kbd *kbd =
            container_of(node, struct kbd, global_node);
        res = flat_mount_insert_node(
                mnt,
                &kbd->flat_fs_node,
                node->key);
        if(res) {
            spin_unlock(&kbd_tree_lock);
            return res;
        }
    }
    spin_unlock(&kbd_tree_lock);

    res = sysfs_register_mount(&kbd_fs_mount->fs_mount, "kbd");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, kbd_init_fs_mount, "Registering kbd Sysfs Mount");

static struct fs_node_ops
kbd_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .flush = fs_node_cannot_flush,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static ssize_t 
kbd_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount)
{
    struct fs_node *fs_node =
        file->path->fs_node;
    struct kbd *kbd =
        container_of(fs_node, struct kbd, flat_fs_node.fs_node);

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
            dprintk("kbd_read: (SLEEPING)\n");
            wait_on(kbd->read_queue);
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


static struct fs_file_ops
kbd_fs_file_ops = {
    .read = kbd_fs_file_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

