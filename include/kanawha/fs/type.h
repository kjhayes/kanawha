#ifndef __KANAWHA__FS_TYPE_H__
#define __KANAWHA__FS_TYPE_H__

#include <kanawha/ops.h>
#include <kanawha/stdint.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>

struct fs_type;
struct fs_mount;
struct fs_node;

#define FS_TYPE_MOUNT_FILE_SIG(RET,ARG)\
RET(int)\
ARG(struct fs_node *, node)\
ARG(struct fs_mount **, out_mnt)\

#define FS_TYPE_MOUNT_SPECIAL_SIG(RET,ARG)\
RET(int)\
ARG(const char *, id)\
ARG(struct fs_mount **, out_mnt)

#define FS_TYPE_UNMOUNT_SIG(RET,ARG)\
RET(int)\
ARG(struct fs_mount *, mnt)

#define FS_TYPE_OP_LIST(OP, ...)\
OP(mount_file, FS_TYPE_MOUNT_FILE_SIG, ##__VA_ARGS__)\
OP(mount_special, FS_TYPE_MOUNT_SPECIAL_SIG, ##__VA_ARGS__)\
OP(unmount, FS_TYPE_UNMOUNT_SIG, ##__VA_ARGS__)\

struct fs_type {
DECLARE_OP_LIST_PTRS(FS_TYPE_OP_LIST, struct fs_type *)
    struct stree_node fs_type_node;
};

DEFINE_OP_LIST_WRAPPERS(
        FS_TYPE_OP_LIST,
        static inline,
        /* No Prefix */,
        fs_type,
        ->,
        SELF_ACCESSOR)

// Keeps a reference to name
int register_fs_type(
        struct fs_type *type,
        char *name);

struct fs_type *
fs_type_find(const char *name);

// Always Fail Implementations
// (For FS types which are all special or all file-backed)
int
fs_type_cannot_mount_file(
        struct fs_type *type,
        struct fs_node *node,
        struct fs_mount **out);

int
fs_type_cannot_mount_special(
        struct fs_type *type,
        const char *id,
        struct fs_mount **out);

#endif
