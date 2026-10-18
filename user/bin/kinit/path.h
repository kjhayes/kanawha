#ifndef __KINIT__PATH_H__
#define __KINIT__PATH_H__

struct kinit_path;

struct kinit_path *
kinit_create_dir(
        const char *name);

struct kinit_path *
kinit_create_mountpoint(
        const char *name,
        const char *source,
        const char *fs_type,
        unsigned long mount_flags
        );

int
kinit_path_append_child(
        struct kinit_path *parent,
        struct kinit_path *child);

int
kinit_path_set_root(
        struct kinit_path *root);
struct kinit_path *
kinit_path_get_root(void);

int
kinit_activate_root_path(void);

#endif
