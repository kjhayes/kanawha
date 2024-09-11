#ifndef __KANAWHA__FS_PATH_H__
#define __KANAWHA__FS_PATH_H__

#include <kanawha/list.h>
#include <kanawha/process.h>
#include <kanawha/spinlock.h>

struct fs_mount;

#define FS_PATH_MOUNT_POINT (1UL<<0)

struct fs_path
{
    char *name;
    struct fs_node *fs_node;

    unsigned long refs;
    unsigned long flags;

    struct fs_path *parent;
    ilist_t children;
    ilist_node_t child_node;
};

int
fs_path_get(struct fs_path *path);

int
fs_path_put(struct fs_path *path);

int
fs_path_mount_root(
        struct fs_mount *mnt,
        struct fs_path **out);

int
fs_path_mount_dir(
        struct fs_path *parent,
        const char *name,
        struct fs_mount *mnt,
        struct fs_path **out);

int
fs_path_unmount(
        struct fs_path *mnt_point);

int
fs_path_lookup_for_process(
        struct process *process,
        const char *path_str,
        unsigned long access_flags,
        unsigned long mode_flags,
        struct fs_path **out);

#endif
