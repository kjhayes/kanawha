#ifndef __KANAWHA__ROOT_FS_H__
#define __KANAWHA__ROOT_FS_H__

#include <kanawha/fs.h>
#include <kanawha/init.h>

static int
mount_root_fs(void)
{
    int res;

    const char *file_path = CONFIG_ROOT_FS_FILE;
    const char *mnt_name = CONFIG_ROOT_FS_MOUNT_NAME;
    const char *fs_name = CONFIG_ROOT_FS_FILESYSTEM;

    struct fs_type *type =
        fs_type_find(fs_name);
    if(type == NULL) {
        eprintk("Cannot find root fs filesystem type \"%s\"\n",
                fs_name);
        return -ENXIO;
    }

    struct fs_mount *backing_mount;
    struct fs_node *backing_file;
    res = fs_path_lookup(
            file_path,
            &backing_mount,
            &backing_file);
    if(res) {
        return res;
    } 

    struct fs_mount *root_fs_mnt;

    res = fs_type_mount_file(
            type,
            backing_file,
            &root_fs_mnt);
    if(res) {
        fs_mount_put_node(backing_mount, backing_file);
        return res;
    }
    fs_mount_put_node(backing_mount, backing_file);

    res = fs_attach_mount(
            root_fs_mnt,
            mnt_name);
    if(res) {
        fs_type_unmount(type, root_fs_mnt);
        return res;
    }

    return 0;
}

declare_init_desc(late, mount_root_fs, "Mounting Root FS");

#endif
