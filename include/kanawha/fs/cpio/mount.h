#ifndef __KANAWHA__FS_CPIO_MOUNT_H__
#define __KANAWHA__FS_CPIO_MOUNT_H__

#include <kanawha/fs/cpio/cpio.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/cpio/dir.h>

struct cpio_mount
{
    struct fs_mount fs_mount;

    cpio_type_t type;
    struct fs_node *backing_file;

    struct cpio_dir_node root_node;
};


int
cpio_read_header(
        struct cpio_mount *mnt,
        size_t offset,
        struct cpio_header *hdr);

#endif
