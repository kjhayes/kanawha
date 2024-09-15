
#include <kanawha/fs/cpio/cpio.h>
#include <kanawha/fs/cpio/file.h>
#include <kanawha/fs/cpio/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>

#define CPIO_FILE_PAGE_ORDER 12

static int
cpio_file_flush(
        struct file *file,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node =
        file->path->fs_node;

    res = fs_node_flush(fs_node);
    if(res) {
        return res;
    }

    return 0;
}

struct fs_file_ops
cpio_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = cpio_file_flush,

    .dir_next = fs_file_cannot_dir_next,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
cpio_node_read_page(
        struct fs_node *node,
        void *buf,
        uintptr_t pfn)
{
    int res;

    struct cpio_file_node *cpio_file =
        container_of(node, struct cpio_file_node, fs_node);

    uintptr_t offset =
        pfn << CPIO_FILE_PAGE_ORDER;

    uintptr_t backing_offset =
        cpio_file->data_offset + offset;

    size_t data_size = cpio_file->data_size - offset;
    size_t page_size = 1ULL<<CPIO_FILE_PAGE_ORDER;

    size_t to_read = data_size < page_size ? data_size : page_size;

    void *original_buf = buf;

    res = fs_node_paged_read(
            cpio_file->mnt->backing_file,
            backing_offset,
            buf,
            to_read);
    if(res) {
        return res;
    }

    if(data_size < page_size) {
        memset(buf + data_size, 0, page_size - data_size);
    }

    return 0;
}

static int
cpio_node_write_page(
        struct fs_node *node,
        void *buf,
        uintptr_t pfn)
{
    int res;

    struct cpio_file_node *cpio_file =
        container_of(node, struct cpio_file_node, fs_node);

    uintptr_t offset =
        pfn << CPIO_FILE_PAGE_ORDER;

    uintptr_t backing_offset =
        cpio_file->data_offset + offset;

    size_t data_size = cpio_file->data_size - offset;
    size_t page_size = 1ULL<<CPIO_FILE_PAGE_ORDER;

    size_t to_read = data_size < page_size ? data_size : page_size;

    void *original_buf = buf;

    res = fs_node_paged_write(
            cpio_file->mnt->backing_file,
            backing_offset,
            buf,
            to_read);
    if(res) {
        return res;
    }

    return 0;
}

static int
cpio_node_flush(
        struct fs_node *node)
{
    int res;

    struct cpio_file_node *cpio_file =
        container_of(node, struct cpio_file_node, fs_node);

    res = fs_node_flush(cpio_file->mnt->backing_file);
    if(res) {
        return res;
    }

    return 0;
}

static int
cpio_node_getattr(
        struct fs_node *node,
        int attr,
        size_t *value)
{
    struct cpio_file_node *cpio_file =
        container_of(node, struct cpio_file_node, fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = cpio_file->data_size;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = CPIO_FILE_PAGE_ORDER;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static int
cpio_node_setattr(
        struct fs_node *node,
        int attr,
        size_t value)
{
    // Cannot set any attributes of a CPIO node
    return -EINVAL;
}

struct fs_node_ops
cpio_node_ops = {
    .read_page = cpio_node_read_page,
    .write_page = cpio_node_write_page,
    .flush = cpio_node_flush,
    .getattr = cpio_node_getattr,
    .setattr = cpio_node_setattr,

    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

