

#include <kanawha/fs/node.h>

#include <kanawha/ptree.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/slab.h>
#include <kanawha/errno.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/page_alloc.h>

static int __klog_boot_frames_used = 0;
static uint8_t __klog_boot_frames[CONFIG_KLOG_BOOT_FRAMES * CONFIG_KLOG_FRAMESIZE];

static DECLARE_PTREE(klog_tree);
DEFINE_LOCAL_IRQ_LOCK(klog_tree_lock);

#define KLOG_FRAME_SLAB_BUFFER_SIZE 0x1000
static uint8_t klog_frame_slab_buffer[KLOG_FRAME_SLAB_BUFFER_SIZE];
static struct slab_allocator *klog_frame_slab_allocator = NULL;
DEFINE_LOCAL_IRQ_LOCK(klog_frame_slab_lock);

struct klog_frame
{
    struct ptree_node tree_node;

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
    klog_frame_slab_lock_acquire();
    struct klog_frame *frame = slab_alloc(klog_frame_slab_allocator);

    memset(frame, 0, sizeof(struct klog_frame));

    if(__klog_boot_frames_used < CONFIG_KLOG_BOOT_FRAMES) {
        frame->data = ((void*)__klog_boot_frames) + (CONFIG_KLOG_FRAMESIZE * __klog_boot_frames_used);
        __klog_boot_frames_used++;
    } else {
        frame->data = kmalloc(CONFIG_KLOG_FRAMESIZE, KM_KERNEL);
    }

    if(frame->data == NULL) {
        slab_free(klog_frame_slab_allocator, frame);
        klog_frame_slab_lock_release();
        return NULL;
    }

    frame->total_len = CONFIG_KLOG_FRAMESIZE;
    frame->filled_len = 0;

    klog_frame_slab_lock_release();

    return frame;
}

int
klog_putc(char c)
{
    klog_tree_lock_acquire();

    struct ptree_node *node = ptree_get_last(&klog_tree);
    struct klog_frame *frame;
    if(node == NULL) {
        struct klog_frame *first_frame = klog_frame_alloc();
        if(first_frame == NULL) {
            klog_tree_lock_release();
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
            klog_tree_lock_release();
            return -ENOMEM;
        }
        ptree_insert(&klog_tree, &new_frame->tree_node, offset);
        frame = new_frame;
    }

    frame->data[frame->filled_len] = c;
    frame->filled_len++;

    klog_tree_lock_release();
    return 0;
}

/*
 * klog Sysfs Bindings
 */

#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>

static struct vfs_mount *klog_fs_mount = NULL;

static struct fs_node_ops klog_fs_node_ops;
static struct fs_file_ops klog_fs_file_ops;
static struct vfs_node klog_fs_node = { 0 };

static struct fs_node_ops kmem_free_fs_node_ops;
static struct fs_file_ops kmem_free_fs_file_ops;
static struct vfs_node kmem_free_fs_node = { 0 };

static int
klog_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create klog vfs mount!\n");
        return -ENOMEM;
    }

    klog_fs_mount = mnt;

    klog_fs_node.fs_file_ops = &klog_fs_file_ops;
    klog_fs_node.fs_node_ops = &klog_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            mnt,
            &klog_fs_node,
            "klog");
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    kmem_free_fs_node.fs_file_ops = &kmem_free_fs_file_ops;
    kmem_free_fs_node.fs_node_ops = &kmem_free_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            mnt,
            &kmem_free_fs_node,
            "free");
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&klog_fs_mount->fs_mount, "info");
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, klog_init_fs_mount, "Registering klog Sysfs Mount");

static ssize_t 
klog_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;

    struct fs_path *path = file->path;
    res = fs_path_get(path);
    if(res) {
        return res;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(path);

    size_t offset = file->seek_offset;

    klog_tree_lock_acquire();

    struct ptree_node *node = ptree_get_max_less_or_eq(&klog_tree, offset);
    if(node == NULL) {
        klog_tree_lock_release();
        fs_path_put(path);
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

    klog_tree_lock_release();

    fs_path_put(path);

    return amount;
}

static struct fs_node_ops
klog_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_flush_nop,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static struct fs_file_ops
klog_fs_file_ops = {
    .read = klog_fs_file_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static ssize_t 
kmem_free_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    if(file->seek_offset != 0) {
        return 0;
    }
    snprintk(buffer, amount, "%lu", (ul_t)page_alloc_amount_free());
    ((char*)buffer)[amount-1] = '\0';
    return strlen(buffer);
}

static struct fs_node_ops
kmem_free_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_flush_nop,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static struct fs_file_ops
kmem_free_fs_file_ops = {
    .read = kmem_free_fs_file_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

