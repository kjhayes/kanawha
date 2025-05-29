
#include <acpi/acpi.h>
#include <acpi/table.h>
#include <kanawha/errno.h>
#include <kanawha/string.h>
#include <kanawha/init.h>
#include <kanawha/lock.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/sysfs.h>
#include <kanawha/fs/sys/vfs.h>

static DECLARE_ILIST(sysfs_temp_list);
DEFINE_LOCAL_THREAD_LOCK(sysfs_lock);

static struct vfs_mount *acpi_fs_mount = NULL;
static struct fs_node_ops acpi_fs_node_ops;
static struct fs_file_ops acpi_fs_file_ops;

#define ACPI_SYSFS_PAGE_ORDER VMEM_MIN_PAGE_ORDER

static int
acpi_fs_node_read_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    struct acpi_table *ptr =
        container_of(fs_node, struct acpi_table, sysfs_node.fs_node);

    uintptr_t offset = pfn << ACPI_SYSFS_PAGE_ORDER;
    ssize_t room_left = ptr->table->hdr.length - offset;
    if(room_left > (1ULL<<ACPI_SYSFS_PAGE_ORDER)) {
        room_left = 1ULL<<ACPI_SYSFS_PAGE_ORDER;
    }

    if(room_left <= 0) {
        return -ENXIO;
    }

    // Zero the entire buffer no matter what (TODO: We could be smarter about this)
    memset(buffer, 0, (1ULL<<ACPI_SYSFS_PAGE_ORDER));

    // Copy whatever data we can
    memcpy(buffer, (void*)ptr->table, room_left);

    return 0;
}

static int
acpi_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    int res;

    struct acpi_table *ptr =
        container_of(fs_node, struct acpi_table, sysfs_node.fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = ptr->table->hdr.length;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = ACPI_SYSFS_PAGE_ORDER;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static struct fs_node_ops
acpi_fs_node_ops = {
    .read_page = acpi_fs_node_read_page,
    .write_page = fs_node_cannot_write_page,
    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_cannot_flush,
    .getattr = acpi_fs_node_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,

};
static struct fs_file_ops
acpi_fs_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_paged_seek,
    .poll = fs_file_cannot_poll,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

// NOTE: Assumes that sysfs_lock is held
static int
do_register_table(
        struct acpi_table *table)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(acpi_fs_mount));

    table->sysfs_node.fs_node.node_ops = &acpi_fs_node_ops;
    table->sysfs_node.fs_node.file_ops = &acpi_fs_file_ops;

    size_t inode;
    res = vfs_mount_insert_node(
            acpi_fs_mount,
            &table->sysfs_node,
            &inode);
    if(res) {
        return res;
    }

    res = vfs_mount_link_root(
            acpi_fs_mount,
            table->signature_str,
            inode);
    if(res) {
        vfs_mount_remove_node(
                acpi_fs_mount,
                &table->sysfs_node);
        return res;
    }

    return 0;
}

static int
acpi_sysfs_init_mount(void)
{
    int res;
    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        return -ENOMEM;
    }

    sysfs_lock_acquire();
    acpi_fs_mount = mnt;
    ilist_node_t *node;
    ilist_for_each(node, &sysfs_temp_list) {
        struct acpi_table *ptr = container_of(node, struct acpi_table, sysfs_temp_list_node);
        res = do_register_table(ptr);
        if(res) {
            sysfs_lock_release();
            return res;
        }
    }

    res = sysfs_register_mount(
            &acpi_fs_mount->fs_mount,
            "acpi");
    if(res) {
        return res;
    }

    sysfs_lock_release();

    return 0;
}
declare_init_desc(fs, acpi_sysfs_init_mount, "Registering ACPI Sysfs Mount");

int
acpi_sysfs_on_register_table(
        struct acpi_table *table)
{
    int res;

    sysfs_lock_acquire();

    if(acpi_fs_mount == NULL) {
        ilist_push_tail(&sysfs_temp_list, &table->sysfs_temp_list_node);
        sysfs_lock_release();
        return 0;
    }

    res = do_register_table(table);
    sysfs_lock_release();
    return res;
}

