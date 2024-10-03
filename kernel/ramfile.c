
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/flat.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/file.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>

struct fs_node_ops;

struct ramfile
{
    spinlock_t lock;
    struct flat_node flat_node;

    size_t page_refs;

    paddr_t paddr;
    size_t size;
    order_t page_order;
};

static struct flat_mount *ramfile_flat_mount = NULL;

#define RAMFILE_FROM_FS_NODE(fs_node_ptr)\
    ({ (struct ramfile *)container_of(\
            container_of(fs_node_ptr, struct flat_node, fs_node),\
            struct ramfile,\
            flat_node); })

static int
ramfile_read_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn)
{
    int res;

    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(fs_node);

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res) {
        return res;
    }

    spin_lock(&ramfile->lock);

    uintptr_t offset = pfn << order;
    uintptr_t page_end_offset = offset + (1ULL<<order);

    if(page_end_offset > ramfile->size) {
        page_end_offset = ramfile->size;
    }

    dprintk("ramfile_read_page: offset=%p, page_end_offset=%p\n",
            offset, page_end_offset);

    ssize_t copy_size = page_end_offset - offset;
    DEBUG_ASSERT(copy_size >= 0);

    void *data = (void*)__va(ramfile->paddr);
    memmove(buffer, data + offset, copy_size);

    ssize_t room_left = (1ULL<<order) - copy_size;
    memset(buffer + copy_size, 0, room_left);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_write_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn)
{
    int res;

    dprintk("ramfile_write_page\n");

    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(fs_node);

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res) {
        return res;
    }

    spin_lock(&ramfile->lock);

    uintptr_t offset = pfn << order;
    uintptr_t page_end_offset = offset + (1ULL<<order);

    if(page_end_offset > ramfile->size) {
        page_end_offset = ramfile->size;
    }

    dprintk("offset=%p page_end_offset=%p\n",
            offset, page_end_offset);

    ssize_t copy_size = page_end_offset - offset;
    DEBUG_ASSERT(copy_size >= 0);

    void *data = (void*)__va(ramfile->paddr);
    memmove(data + offset, buffer, copy_size);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_node_flush(
        struct fs_node *fs_node)
{
    // TODO: Flush caches of any CPU(s) which might have written
    // to this ramfile (only needed with a weaker memory model)

    return 0;
}

static int
ramfile_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    int res;

    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = ramfile->size;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = ramfile->page_order;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static int
ramfile_node_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    return -EINVAL;
}

static int
ramfile_mount_init(void)
{
    int res;

    ramfile_flat_mount = flat_mount_create();
    if(ramfile_flat_mount == NULL) {
        return -ENOMEM;
    }

    return 0;
}
declare_init_desc(bus, ramfile_mount_init, "Attaching ramfile Mount");

static int
ramfile_register_sysfs(void)
{
    int res;

    if(ramfile_flat_mount == NULL) {
        return -EDEFER;
    }

    res = sysfs_register_mount(
            &ramfile_flat_mount->fs_mount,
            "ramfile");
    if(res) {
        return res;
    }

    return 0;
}
declare_init(late, ramfile_register_sysfs);

struct fs_mount *
ramfile_mount(void)
{
    return &ramfile_flat_mount->fs_mount;
}

struct fs_node_ops
ramfile_fs_node_ops =
{
    .read_page = ramfile_read_page,
    .write_page = ramfile_write_page,
    .flush = ramfile_node_flush,

    .getattr = ramfile_node_getattr,
    .setattr = ramfile_node_setattr,

    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

struct fs_file_ops
ramfile_fs_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,

    .flush = fs_file_nop_flush,

    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

int
create_ramfile(
        const char *ramfile_name,
        paddr_t paddr,
        size_t size)
{
    int res;

    if(ramfile_flat_mount == NULL) {
        return -EDEFER;
    }

    struct ramfile *ramfile =
        kmalloc(sizeof(struct ramfile));
    if(ramfile == NULL) {
        return -ENOMEM;
    }
    memset(ramfile, 0, sizeof(struct ramfile));

    ramfile->size = size;
    ramfile->paddr = paddr;
    ramfile->page_order = 12;
    spinlock_init(&ramfile->lock);

    order_t base_order = ptr_orderof(paddr);
    order_t end_order = ptr_orderof(paddr + size);

    ramfile->page_refs = 0;

    ramfile->flat_node.fs_node.file_ops = &ramfile_fs_file_ops;
    ramfile->flat_node.fs_node.node_ops = &ramfile_fs_node_ops;

    res = flat_mount_insert_node(
            ramfile_flat_mount,
            &ramfile->flat_node,
            ramfile_name);
    if(res) {
        kfree(ramfile);
        return res;
    }

    return 0;
}

int
destroy_ramfile(
        const char *ramfile_name)
{
    return -EUNIMPL;
}

struct fs_node *
ramfile_get(const char *name)
{
    int res;

    if(ramfile_flat_mount == NULL) {
        return NULL;
    }

    size_t root_index;
    res = fs_mount_root_index(
            &ramfile_flat_mount->fs_mount,
            &root_index);
    if(res) {
        return NULL;
    }

    struct fs_node *root_node =
        fs_mount_get_node(
                &ramfile_flat_mount->fs_mount,
                root_index);
    if(root_node == NULL) {
        return NULL;
    }

    size_t inode;
    res = fs_node_lookup(
            root_node,
            name,
            &inode);
    if(res) {
        fs_node_put(root_node);
        return NULL;
    }

    struct fs_node *ramfile_node;
    ramfile_node = fs_mount_get_node(
            &ramfile_flat_mount->fs_mount,
            inode);
    if(ramfile_node == NULL) {
        fs_node_put(root_node);
        return NULL;
    }

    fs_node_put(root_node);
    return ramfile_node;
}

int
ramfile_put(
        struct fs_node *node)
{
    if(ramfile_flat_mount == NULL) {
        return -EINVAL;
    }
    return fs_node_put(node);
}

