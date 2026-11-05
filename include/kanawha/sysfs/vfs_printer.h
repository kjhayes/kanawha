#ifndef __KANAWHA__VFS_PRINTER_H__
#define __KANAWHA__VFS_PRINTER_H__

#include <kanawha/sysfs/vfs.h>

// "printer" node(s)
/*
 * This is really just a "quality-of-life" feature, as having
 * VFS nodes which just print using "snprintk" and cannot be written
 * is pretty common
 */

struct printer;

struct vfs_printer_node
{
    struct vfs_node vfs_node;
    int(*print)(
            struct vfs_printer_node *node,
            struct printer *p);
};

int
vfs_init_printer_node(
        struct vfs_printer_node *node,
        int(*print)(
            struct vfs_printer_node *,
            struct printer *));

int
vfs_deinit_printer_node(
        struct vfs_printer_node *node);

struct vfs_node *
vfs_printer_node_as_vfs_node(
    struct vfs_printer_node *);

#endif
