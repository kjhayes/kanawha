
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/slab.h>
#include <kanawha/errno.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/init.h>

static int __klog_boot_frames_used = 0;
static uint8_t __klog_boot_frames[CONFIG_KLOG_BOOT_FRAMES * CONFIG_KLOG_FRAMESIZE];

static DECLARE_PTREE(klog_tree);
static DECLARE_SPINLOCK(klog_tree_lock);

static DECLARE_SPINLOCK(klog_frame_slab_lock);
#define KLOG_FRAME_SLAB_BUFFER_SIZE 0x1000
static uint8_t klog_frame_slab_buffer[KLOG_FRAME_SLAB_BUFFER_SIZE];
static struct slab_allocator *klog_frame_slab_allocator = NULL;

struct klog_frame
{
    struct ptree_node tree_node;

    spinlock_t lock;

    size_t total_len;
    size_t filled_len;
    char *data;
};

int
klog_init(void) 
{
    klog_frame_slab_allocator = create_static_slab_allocator(
            klog_frame_slab_buffer,
            KLOG_FRAME_SLAB_BUFFER_SIZE,
            sizeof(struct klog_frame),
            orderof(struct klog_frame));

    if(klog_frame_slab_allocator == NULL) {
        return -ENOMEM;
    }

    return 0;
}

static struct klog_frame *
klog_frame_alloc(void)
{
    int irq_flags = spin_lock_irq_save(&klog_frame_slab_lock);
    struct klog_frame *frame = slab_alloc(klog_frame_slab_allocator);

    memset(frame, 0, sizeof(struct klog_frame));
    spinlock_init(&frame->lock);

    if(__klog_boot_frames_used < CONFIG_KLOG_BOOT_FRAMES) {
        frame->data = ((void*)__klog_boot_frames) + (CONFIG_KLOG_FRAMESIZE * __klog_boot_frames_used);
        __klog_boot_frames_used++;
    } else {
        frame->data = kmalloc(CONFIG_KLOG_FRAMESIZE);
    }

    if(frame->data == NULL) {
        slab_free(klog_frame_slab_allocator, frame);
        spin_unlock_irq_restore(&klog_frame_slab_lock, irq_flags);
        return NULL;
    }

    frame->total_len = CONFIG_KLOG_FRAMESIZE;
    frame->filled_len = 0;

    spin_unlock_irq_restore(&klog_frame_slab_lock, irq_flags);

    return frame;
}

int
klog_putc(char c)
{
    int irq_flags = spin_lock_irq_save(&klog_tree_lock);

    struct ptree_node *node = ptree_get_last(&klog_tree);
    struct klog_frame *frame;
    if(node == NULL) {
        struct klog_frame *first_frame = klog_frame_alloc();
        if(first_frame == NULL) {
            spin_unlock_irq_restore(&klog_tree_lock, irq_flags);
            return -ENOMEM;
        }
        ptree_insert(&klog_tree, &first_frame->tree_node, 0);
        frame = first_frame;
    }
    else {
        frame = container_of(node, struct klog_frame, tree_node);
    }

    if(frame->total_len <= frame->filled_len) {
        size_t offset = frame->tree_node.key + frame->total_len;
        struct klog_frame *new_frame = klog_frame_alloc();
        if(new_frame == NULL) {
            spin_unlock_irq_restore(&klog_tree_lock, irq_flags);
            return -ENOMEM;
        }
        ptree_insert(&klog_tree, &new_frame->tree_node, offset);
    }

    frame->data[frame->filled_len] = c;
    frame->filled_len++;

    spin_unlock_irq_restore(&klog_tree_lock, irq_flags);
    return 0;
}

/*
 * klog Sysfs Bindings
 */

#include <kanawha/fs/flat.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>

static struct flat_mount *klog_fs_mount = NULL;
static struct fs_node_ops klog_fs_node_ops;
static struct fs_file_ops klog_fs_file_ops;

static struct flat_node klog_fs_node = { 0 };

static int
klog_init_fs_mount(void)
{
    int res;

    struct flat_mount *mnt;
    mnt = flat_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create flat mount!\n");
        return -ENOMEM;
    }

    klog_fs_mount = mnt;

    klog_fs_node.fs_node.unload = NULL;
    klog_fs_node.fs_node.file_ops = &klog_fs_file_ops;
    klog_fs_node.fs_node.node_ops = &klog_fs_node_ops;

    res = flat_mount_insert_node(
            mnt,
            &klog_fs_node,
            "klog");
    if(res) {
        return res;
    }

    res = sysfs_register_mount(&klog_fs_mount->fs_mount, "log");
    if(res) {
        return res;
    }

    return 0;
}
declare_init_desc(fs, klog_init_fs_mount, "Registering klog Sysfs Mount");


static struct fs_node_ops
klog_fs_node_ops =
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
klog_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount)
{
    struct fs_node *fs_node =
        file->path->fs_node;

    size_t offset = file->seek_offset;

    int irq_flags = spin_lock_irq_save(&klog_tree_lock);

    struct ptree_node *node = ptree_get_max_less_or_eq(&klog_tree, offset);
    if(node == NULL) {
        spin_unlock_irq_restore(&klog_tree_lock, irq_flags);
        return 0;
    }

    struct klog_frame *frame =
        container_of(node, struct klog_frame, tree_node);

    size_t rel_offset = offset - frame->tree_node.key;
    size_t room_left = frame->filled_len - rel_offset;

    if(room_left < amount) {
        amount = room_left;
    }

    memcpy(buffer, frame->data + rel_offset, amount);

    spin_unlock_irq_restore(&klog_tree_lock, irq_flags);

    return amount;
}
static struct fs_file_ops
klog_fs_file_ops = {
    .read = klog_fs_file_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

