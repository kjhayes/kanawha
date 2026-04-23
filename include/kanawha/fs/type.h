#ifndef __KANAWHA__FS_TYPE_H__
#define __KANAWHA__FS_TYPE_H__

#include <kanawha/ops.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/types.h>

struct fs_type;
struct fs_mount;
struct fs_node;

#define FS_TYPE_PROBE_MAYBE   (0)
#define FS_TYPE_PROBE_VALID   (1)
#define FS_TYPE_PROBE_INVALID (2)
#define FS_TYPE_PROBE_SIG(RET,ARG,...)\
    RET(int) \
    ARG(struct fs_node *, node)

#define FS_TYPE_MOUNT_FILE_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(struct fs_node *, node)                                                \
    ARG(struct fs_mount **, out_mnt)

#define FS_TYPE_MOUNT_SPECIAL_SIG(RET, ARG, ...)                               \
    RET(int)                                                                   \
    ARG(const char *, id)                                                      \
    ARG(struct fs_mount **, out_mnt)

#define FS_TYPE_UNMOUNT_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(struct fs_mount *, mnt)

#define FS_TYPE_OP_LIST(OP, ...)                                               \
    OP(probe, FS_TYPE_PROBE_SIG, ##__VA_ARGS__)                      \
    OP(mount_file, FS_TYPE_MOUNT_FILE_SIG, ##__VA_ARGS__)                      \
    OP(mount_special, FS_TYPE_MOUNT_SPECIAL_SIG, ##__VA_ARGS__)                \
    OP(unmount, FS_TYPE_UNMOUNT_SIG, ##__VA_ARGS__)

struct fs_type
{
    DECLARE_OP_LIST_PTRS(FS_TYPE_OP_LIST, struct fs_type *)
    struct stree_node fs_type_node;
};

#define FS_TYPE_OPS_ACCESSOR(__self, __field) __self->__field

DEFINE_OP_LIST_WRAPPERS(FS_TYPE_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        fs_type,
                        FS_TYPE_OPS_ACCESSOR,
                        SELF_ACCESSOR)

// Keeps a reference to name
int
register_fs_type(struct fs_type *type, char *name);

struct fs_type *
fs_type_find(const char *name);

// Fixed response implementations of "fs_type_probe"

int
fs_type_probe_always_maybe(
        struct fs_type *type,
        struct fs_node *node);
int
fs_type_probe_always_invalid(
        struct fs_type *type,
        struct fs_node *node);
int
fs_type_probe_always_valid(
        struct fs_type *type,
        struct fs_node *node);

// Always Fail Implementations
// (For FS types which are all special or all file-backed)
int
fs_type_cannot_mount_file(struct fs_type *type,
                          struct fs_node *node,
                          struct fs_mount **out);

int
fs_type_cannot_mount_special(struct fs_type *type,
                             const char *id,
                             struct fs_mount **out);

#endif
