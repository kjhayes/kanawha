#ifndef __KANAWHA__FS_CPIO_DIR_H__
#define __KANAWHA__FS_CPIO_DIR_H__

#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/cpio/cpio.h>

extern struct fs_file_ops cpio_dir_file_ops;
extern struct fs_node_ops cpio_dir_node_ops;

struct cpio_mount;

struct cpio_dir_node
{
    struct fs_node fs_node;
    struct cpio_mount *mnt;
};


#endif
