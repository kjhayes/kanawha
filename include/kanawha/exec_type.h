#ifndef __KANAWHA__EXEC_TYPE_H__
#define __KANAWHA__EXEC_TYPE_H__

#include <kanawha/fs/file.h>
#include <kanawha/ops.h>
#include <kanawha/registry.h>

struct exec_type;
struct exec_type_ops;

#define EXEC_TYPE_PROBE_REJECT                                                 \
    (0) // This file is definitely not valid for this type
#define EXEC_TYPE_PROBE_CLAIM (1) // This file is definitely valid for this type
#define EXEC_TYPE_PROBE_MAYBE (2) // Unsure just from the header data provided
#define EXEC_TYPE_PROBE_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(struct process *, process)                                             \
    ARG(struct file *, desc)

#define EXEC_TYPE_LOAD_SIG(RET, ARG, ...)                                      \
    RET(int)                                                                   \
    ARG(struct process *, process)                                             \
    ARG(struct file *, desc)

#define EXEC_TYPE_PRGET_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(struct process *, process)                                             \
    ARG(long, field)                                                           \
    ARG(unsigned long *, value)

#define EXEC_TYPE_PRSET_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(struct process *, process)                                             \
    ARG(long, field)                                                           \
    ARG(unsigned long, value)

#define EXEC_TYPE_OP_LIST(OP, ...)                                             \
    OP(probe, EXEC_TYPE_PROBE_SIG, ##__VA_ARGS__)                              \
    OP(load, EXEC_TYPE_LOAD_SIG, ##__VA_ARGS__)

struct exec_type_ops
{
    DECLARE_OP_LIST_PTRS(EXEC_TYPE_OP_LIST, struct exec_type *);
};

struct exec_type
{
    struct exec_type_ops *ops;
    struct registry_node registry_node;
};

DEFINE_OP_LIST_WRAPPERS(EXEC_TYPE_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        exec_type,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR);

DECLARE_REGISTRY(exec_type);

#undef EXEC_TYPE_PROBE_SIG
#undef EXEC_TYPE_LOAD_SIG
#undef EXEC_TYPE_OP_LIST

/*
 * Default Method Implementations
 */

// NOTE: If any registered exec_type(s) use this function,
// then trying to execute a non-executable file will always
// kill the current process.
int
exec_type_probe_always_maybe(struct exec_type *exec_type,
                             void *hdr,
                             size_t hdrlen);

#endif
