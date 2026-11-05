

#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/vfs_printer.h>
#include <kanawha/printer.h>

static struct fs_node_ops vfs_printer_node_node_ops;
static struct fs_file_ops vfs_printer_node_file_ops;

int
vfs_init_printer_node(
        struct vfs_printer_node *node,
        int(*print)(
            struct vfs_printer_node *node,
            struct printer *p)
        )
{
    node->print = print;
    node->vfs_node.fs_node_ops = &vfs_printer_node_node_ops;
    node->vfs_node.fs_file_ops = &vfs_printer_node_file_ops;
    return 0;
}

struct vfs_node *
vfs_printer_node_as_vfs_node(
    struct vfs_printer_node *p)
{
    return &p->vfs_node;
}

struct vfs_printer_node_printer {
    char *buffer;
    size_t buflen;
    ssize_t offset;
    size_t amount_copied;
    struct printer printer;
};

static int
vfs_printer_node_printer_putc(
        struct printer *printer,
        char c)
{
    struct vfs_printer_node_printer *p =
        container_of(printer, struct vfs_printer_node_printer, printer);
    if(p->offset >= 0 && p->offset < p->buflen) {
        p->buffer[p->offset] = c;
        p->amount_copied++;
    }
    p->offset++;
    return 0;
}

static ssize_t
vfs_printer_node_fs_file_read(struct file *file,
                  void *buffer,
                  ssize_t amount,
                  unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL) {
        return -EINVAL;
    }

    struct vfs_node *vfs_node = vfs_node_from_fs_node(fs_node);
    if(vfs_node == NULL) {
        fs_node_put(fs_node);
        return -EINVAL;
    }

    struct vfs_printer_node *node =
        container_of(vfs_node, struct vfs_printer_node, vfs_node);

    size_t offset = fs_file_get_seek_offset(file);

    struct vfs_printer_node_printer printer = {
        .buflen = amount,
        .buffer = buffer,
        .amount_copied = 0,
        .offset = -(ssize_t)offset,
        .printer = {
            .putc = vfs_printer_node_printer_putc,
            .puts = printer_puts_using_write,
            .write = printer_write_using_putc,
        },
    };

    (*node->print)(
            node,
            &printer.printer);

    fs_node_put(fs_node);
    return printer.amount_copied;
}

static struct fs_node_ops vfs_printer_node_node_ops = {
    .flush = fs_node_flush_nop,
    VFS_NODE_OPS_INITIALIZERS
};
FS_NODE_OPS_INIT_UNDEF(vfs_printer_node_node_ops);

static struct fs_file_ops vfs_printer_node_file_ops = {
    .read = vfs_printer_node_fs_file_read,
    .write = fs_file_cannot_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_any,
    VFS_FILE_OPS_INITIALIZERS
};
FS_FILE_OPS_INIT_UNDEF(vfs_printer_node_file_ops);

