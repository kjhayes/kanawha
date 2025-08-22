
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/types.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>

struct fs_node_ops;

struct ramfile
{
    spinlock_t lock;
    struct vfs_node vfs_node;

    size_t page_refs;

    void __phys * paddr;
    size_t size;
    order_t page_order;
};

static struct vfs_mount *ramfile_fs_mount = NULL;

#define RAMFILE_FROM_FS_NODE(fs_node_ptr)\
    (container_of(((struct vfs_node*)(fs_node_ptr)->backing.priv_state), struct ramfile, vfs_node))

static int
ramfile_read_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
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

    memcpy_pv(buffer, ramfile->paddr + offset, copy_size);

    ssize_t room_left = (1ULL<<order) - copy_size;
    memset(buffer + copy_size, 0, room_left);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_write_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
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

    memcpy_vp(ramfile->paddr + offset, buffer, copy_size);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_load_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys **addr_out)
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

    void __phys *page; 
    if(page_end_offset > ramfile->size) {
        // This is a problem, allocate a page for the tail
        res = page_alloc(
                order,
                &page,
                0);
        if(res) {
            spin_unlock(&ramfile->lock);
            return res;
        }

        // Copy over the data onto the full page
        memcpy_pp(page, ramfile->paddr + offset, ramfile->size - offset);
        // Clear the rest of the page
        memset_p(page + (ramfile->size - offset), 0, page_end_offset - ramfile->size);

    } else {
        // Just access the page directly
        page = ramfile->paddr + offset;
    }

    *addr_out = page;

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_unload_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr)
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
        // This page must have been allocated in ramfile_load_page

        // Copy over the page data
        memcpy_pp(ramfile->paddr + offset, addr, ramfile->size - offset);

        // Free the backing page
        res = page_free(
                order,
                addr);
        if(res) { 
            spin_unlock(&ramfile->lock);
            return res;
        }

    } else {
        // Nothing to be done
    }

    spin_unlock(&ramfile->lock);

    return 0;
}

// Exact same as "unload" page but we don't actually free the backing data
static int
ramfile_flush_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr)
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

    void __phys *page; 
    if(page_end_offset > ramfile->size) {
        // This page must have been allocated in ramfile_load_page

        // Copy over the page data
        memcpy_pp(ramfile->paddr + offset, addr, ramfile->size - offset);

    } else {
        // Nothing to be done
    }

    spin_unlock(&ramfile->lock);

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

    ramfile_fs_mount = vfs_mount_create();
    if(ramfile_fs_mount == NULL) {
        return -ENOMEM;
    }

    return 0;
}
declare_init_desc(bus, ramfile_mount_init, "Attaching ramfile Mount");

static int
ramfile_register_sysfs(void)
{
    int res;

    if(ramfile_fs_mount == NULL) {
        return -EDEFER;
    }

    res = sysfs_register_mount(
            &ramfile_fs_mount->fs_mount,
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
    return &ramfile_fs_mount->fs_mount;
}

struct fs_node_ops
ramfile_fs_node_ops =
{
    .read_page = ramfile_read_page,
    .write_page = ramfile_write_page,

    .load_page = ramfile_load_page,
    .unload_page = ramfile_unload_page,
    .flush_page = ramfile_flush_page,

    .flush = fs_node_flush_nop,

    .getattr = ramfile_node_getattr,
    .setattr = ramfile_node_setattr,
};
FS_NODE_OPS_INIT_UNDEF(ramfile_fs_node_ops);

struct fs_file_ops
ramfile_fs_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,

    .flush = fs_file_paged_flush,
};
FS_FILE_OPS_INIT_UNDEF(ramfile_fs_file_ops);

int
create_ramfile(
        const char *ramfile_name,
        void __phys * paddr,
        size_t size)
{
    int res;

    if(ramfile_fs_mount == NULL) {
        return -EDEFER;
    }

    struct ramfile *ramfile =
        kzmalloc(sizeof(struct ramfile), KM_KERNEL);
    if(ramfile == NULL) {
        return -ENOMEM;
    }

    ramfile->size = size;
    ramfile->paddr = paddr;
    ramfile->page_order = 12;
    spinlock_init(&ramfile->lock);

    order_t base_order = ptr_orderof(paddr);
    order_t end_order = ptr_orderof(paddr + size);

    ramfile->page_refs = 0;

    ramfile->vfs_node.fs_file_ops = &ramfile_fs_file_ops;
    ramfile->vfs_node.fs_node_ops = &ramfile_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            ramfile_fs_mount,
            &ramfile->vfs_node,
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

