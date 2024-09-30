
#include <kanawha/fs/file.h>
#include <kanawha/string.h>

/*
 * Generic Stub File Implementations
 */

ssize_t
fs_file_cannot_read(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    return -EINVAL;
}
ssize_t
fs_file_cannot_write(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    return -EINVAL;
}
ssize_t
fs_file_cannot_seek(
        struct file *file,
        ssize_t offset,
        int whence)
{
    return -EINVAL;
}
int
fs_file_cannot_flush(
        struct file *file,
        unsigned long flags)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_begin(
        struct file *file)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_next(
        struct file *file)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_readattr(
        struct file *file,
        int attr,
        size_t *value)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_readname(
        struct file *file,
        char *buf,
        size_t buflen)
{
    return -EINVAL;
}

/*
 * Default No-Op (always "succeed") Implementations
 */

// Acts as if zero-sized file
ssize_t
fs_file_eof_read(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    return 0;
}
ssize_t
fs_file_eof_write(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    return 0;
}

// Keeps the seek head pinned to zero
ssize_t
fs_file_seek_pinned_zero(
        struct file *file,
        ssize_t offset,
        int whence)
{
    return (ssize_t)0;
}

// Does nothing and returns zero
int
fs_file_nop_flush(
        struct file *file,
        unsigned long flags)
{
    return 0;
}

/*
 * Read/Write Using fs_node_read_page and fs_node_write_page implementations
 */

ssize_t
fs_file_paged_read(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    int res;
    struct fs_node *fs_node = file->path->fs_node;

    if(buflen == 0) {
        return -EINVAL;
    }

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res) {
        return res;
    }

    size_t file_size;
    res = fs_node_getattr(
            fs_node,
            FS_NODE_ATTR_DATA_SIZE,
            &file_size);
    if(res) {
        return res;
    }

    // Only reads a page at a time
    uintptr_t seek_loc = file->seek_offset;

    if(seek_loc > file_size) {
        return -ERANGE;
    }
    if(seek_loc == file_size) {
        // EOF
        return 0;
    }

    if(seek_loc + buflen > file_size) {
        buflen = file_size - seek_loc;
    }

    uintptr_t seek_pfn = seek_loc >> order;
    uintptr_t page_offset = seek_loc & ((1ULL<<order)-1);
    uintptr_t room_left = (1ULL<<order) - page_offset;

    struct fs_page *page = fs_node_get_page(fs_node, seek_pfn);
    if(page == NULL) {
        return -EINVAL;
    }

    ssize_t to_read = buflen < room_left ? buflen : room_left;

    memcpy(buf, (void*)__va(page->paddr) + page_offset, to_read);

    res = fs_node_put_page(fs_node, page, 0);
    if(res) {
        return res;
    }

    return to_read;
}

ssize_t
fs_file_paged_write(
        struct file *file,
        void *buf,
        ssize_t buflen)
{
    int res;
    struct fs_node *fs_node = file->path->fs_node;

    if(buflen == 0) {
        return -EINVAL;
    }

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res) {
        return res;
    }

    size_t file_size;
    res = fs_node_getattr(
            fs_node,
            FS_NODE_ATTR_DATA_SIZE,
            &file_size);
    if(res) {
        return res;
    }

    // Only writes a page at a time

    uintptr_t seek_loc = file->seek_offset;

    if(seek_loc > file_size) {
        return -ERANGE;
    }
    if(seek_loc == file_size) {
        // EOF
        return 0;
    }

    if(seek_loc + buflen > file_size) {
        buflen = file_size - seek_loc;
    }

    uintptr_t seek_pfn = seek_loc >> order;
    uintptr_t page_offset = seek_loc & ((1ULL<<order)-1);
    uintptr_t room_left = (1ULL<<order) - page_offset;

    struct fs_page *page = fs_node_get_page(fs_node, seek_pfn);
    if(page == NULL) {
        return -EINVAL;
    }

    ssize_t to_write = buflen < room_left ? buflen : room_left;

    memcpy((void*)__va(page->paddr) + page_offset, buf, to_write);

    res = fs_node_put_page(fs_node, page, 1);
    if(res) {
        return res;
    }

    return to_write;
}

// Seek using fs_node_getattr and FS_NODE_ATTR_DATA_SIZE
ssize_t
fs_file_paged_seek(
        struct file *file,
        ssize_t offset,
        int whence)
{
    int res;
    struct fs_node *fs_node = file->path->fs_node;

    size_t data_size;
    res = fs_node_getattr(
            fs_node,
            FS_NODE_ATTR_DATA_SIZE,
            &data_size);

    switch(whence) {
        case FS_FILE_SEEK_CUR:
            file->seek_offset += offset;
            break;
        case FS_FILE_SEEK_END:
            file->seek_offset = data_size + offset;
            break;
        case FS_FILE_SEEK_SET:
            file->seek_offset = 0 + offset;
            break;
        default:
            return -EINVAL;
    }

    if(file->seek_offset > data_size) {
        file->seek_offset = data_size;
    }
    return file->seek_offset;
}

