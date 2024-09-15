#ifndef __KANAWHA__FS_FILE_H__
#define __KANAWHA__FS_FILE_H__

#include <kanawha/ops.h>
#include <kanawha/file.h>
#include <kanawha/fs/node.h>

#define FS_FILE_READ_SIG(RET,ARG)\
RET(ssize_t)\
ARG(void *, buf)\
ARG(ssize_t, buflen)

#define FS_FILE_WRITE_SIG(RET,ARG)\
RET(ssize_t)\
ARG(void *, buf)\
ARG(ssize_t, buflen)

#define FS_FILE_SEEK_CUR 0
#define FS_FILE_SEEK_SET 1
#define FS_FILE_SEEK_END 2

#define FS_FILE_SEEK_SIG(RET,ARG)\
RET(ssize_t)\
ARG(ssize_t, offset)\
ARG(int, whence)

#define FS_FILE_FLUSH_ASYNC (1ULL<<0)

#define FS_FILE_FLUSH_SIG(RET,ARG)\
RET(int)\
ARG(unsigned long, flags)

#define FS_FILE_DIR_BEGIN_SIG(RET,ARG)\
RET(int)

#define FS_FILE_DIR_NEXT_SIG(RET,ARG)\
RET(int)

#define FS_FILE_DIR_READATTR_SIG(RET,ARG)\
RET(int)\
ARG(int, attr)\
ARG(size_t *, value)

#define FS_FILE_DIR_READNAME_SIG(RET,ARG)\
RET(int)\
ARG(char *, buffer)\
ARG(size_t, buflen)

#define FS_FILE_OP_LIST(OP, ...)\
OP(read, FS_FILE_READ_SIG, ##__VA_ARGS__)\
OP(write, FS_FILE_WRITE_SIG, ##__VA_ARGS__)\
OP(seek, FS_FILE_SEEK_SIG, ##__VA_ARGS__)\
OP(flush, FS_FILE_FLUSH_SIG, ##__VA_ARGS__)\
OP(dir_begin, FS_FILE_DIR_BEGIN_SIG, ##__VA_ARGS__)\
OP(dir_next, FS_FILE_DIR_NEXT_SIG, ##__VA_ARGS__)\
OP(dir_readattr, FS_FILE_DIR_READATTR_SIG, ##__VA_ARGS__)\
OP(dir_readname, FS_FILE_DIR_READNAME_SIG, ##__VA_ARGS__)

struct fs_file_ops {
DECLARE_OP_LIST_PTRS(FS_FILE_OP_LIST, struct file*);
};

DEFINE_OP_LIST_WRAPPERS(
        FS_FILE_OP_LIST,
        static inline,
        direct_,
        file,
        ->path->fs_node->file_ops->,
        SELF_ACCESSOR);

#undef FS_FILE_READ_SIG
#undef FS_FILE_WRITE_SIG
#undef FS_FILE_SEEK_SIG
#undef FS_FILE_FLUSH_SIG
#undef FS_FILE_DIR_BEGIN_SIG
#undef FS_FILE_DIR_NEXT_SIG
#undef FS_FILE_DIR_READATTR_SIG
#undef FS_FILE_DIR_READNAME_SIG
#undef FS_FILE_OP_LIST

/*
 * Default Error-Throwing Implementations
 */
ssize_t
fs_file_cannot_read(
        struct file *file,
        void *buf,
        ssize_t buflen);
ssize_t
fs_file_cannot_write(
        struct file *file,
        void *buf,
        ssize_t buflen);
ssize_t
fs_file_cannot_seek(
        struct file *file,
        ssize_t offset,
        int whence);
int
fs_file_cannot_flush(
        struct file *file,
        unsigned long flags);
int
fs_file_cannot_dir_begin(
        struct file *file);
int
fs_file_cannot_dir_next(
        struct file *file);
int
fs_file_cannot_dir_readattr(
        struct file *file,
        int attr,
        size_t *value);
int
fs_file_cannot_dir_readname(
        struct file *file,
        char *buf,
        size_t buflen);

/*
 * Default No-Op (always "succeed") Implementations
 */

// Acts as if zero-sized file
ssize_t
fs_file_eof_read(
        struct file *file,
        void *buf,
        ssize_t buflen);
ssize_t
fs_file_eof_write(
        struct file *file,
        void *buf,
        ssize_t buflen);

// Keeps the seek head pinned to zero
ssize_t
fs_file_seek_pinned_zero(
        struct file *file,
        ssize_t offset,
        int whence);

// Does nothing and returns zero
int
fs_file_nop_flush(
        struct file *file,
        unsigned long flags);

/*
 * Read/Write Using fs_node_read_page and fs_node_write_page implementations
 */

ssize_t
fs_file_paged_read(
        struct file *file,
        void *buf,
        ssize_t buflen);
ssize_t
fs_file_paged_write(
        struct file *file,
        void *buf,
        ssize_t buflen);

// Seek using fs_node_getattr and FS_NODE_ATTR_DATA_SIZE
ssize_t
fs_file_paged_seek(
        struct file *file,
        ssize_t offset,
        int whence);

#endif
