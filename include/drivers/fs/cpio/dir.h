#ifndef __KANAWHA__FS_CPIO_DIR_H__
#define __KANAWHA__FS_CPIO_DIR_H__

#define KEEP_FS_NODE_STRUCT_DEF
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <drivers/fs/cpio/cpio.h>

extern struct fs_file_ops cpio_dir_file_ops;
extern struct fs_node_ops cpio_dir_node_ops;

struct cpio_mount;

struct cpio_dir_node
{
    struct fs_node fs_node;
    struct cpio_mount *mnt;
};


#endif
