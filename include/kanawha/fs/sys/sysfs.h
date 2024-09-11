#ifndef __KANAWHA__FS_SYS_SYSFS_H__
#define __KANAWHA__FS_SYS_SYSFS_H__

#include <kanawha/fs/mount.h>

// Does not keep a reference to id
int
sysfs_register_mount(
        struct fs_mount *mnt,
        const char *id);

int
sysfs_unregister_mount(
        const char *id);

#endif
