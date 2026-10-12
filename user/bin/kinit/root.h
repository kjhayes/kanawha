#ifndef __KINIT__ROOT_H__
#define __KINIT__ROOT_H__

int
kinit_set_root_fs(
        const char *source,
        const char *fs_type,
        unsigned long mount_flags);

#endif
