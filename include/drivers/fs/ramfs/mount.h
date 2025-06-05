#ifndef __KANAWHA__RAMFS_MOUNT_H__
#define __KANAWHA__RAMFS_MOUNT_H__

#include <kanawha/ptree.h>
#include <kanawha/fs/mount.h>

struct ramfs_mount
{
    struct fs_mount fs_mount;
    struct ptree inode_tree;
};

#endif
