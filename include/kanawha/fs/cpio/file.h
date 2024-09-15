#ifndef __KANAWHA__FS_CPIO_FILE_H__
#define __KANAWHA__FS_CPIO_FILE_H__

#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>

extern struct fs_file_ops cpio_file_ops;
extern struct fs_node_ops cpio_node_ops;

struct cpio_file_node
{
    struct fs_node fs_node;
    struct cpio_mount *mnt;

    size_t header_offset;
    size_t data_offset;
    size_t data_size;
};

#endif
