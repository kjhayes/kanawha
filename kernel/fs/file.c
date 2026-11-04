
#include <kanawha/fs/file.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

/*
 * Generic Stub File Implementations
 */

ssize_t
fs_file_cannot_read(struct file *file,
                    void *buf,
                    ssize_t buflen,
                    unsigned long flags)
{
    return -EINVAL;
}
ssize_t
fs_file_cannot_write(struct file *file,
                     void *buf,
                     ssize_t buflen,
                     unsigned long flags)
{
    return -EINVAL;
}
ssize_t
fs_file_cannot_seek(struct file *file, ssize_t offset, int whence)
{
    return -EINVAL;
}
int
fs_file_cannot_flush(struct file *file, unsigned long flags)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_begin(struct file *file)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_next(struct file *file)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_readattr(struct file *file, int attr, size_t *value)
{
    return -EINVAL;
}
int
fs_file_cannot_dir_readname(struct file *file, char *buf, size_t buflen)
{
    return -EINVAL;
}
int
fs_file_cannot_poll(struct file *file,
                    unsigned long watching,
                    unsigned long *triggered)
{
    return -EINVAL;
}

int
fs_file_cannot_status(struct file *file,
                      unsigned long type,
                      unsigned long *value)
{
    return -EINVAL;
}

/*
 * Default No-Op (always "succeed") Implementations
 */

// Acts as if zero-sized file
ssize_t
fs_file_eof_read(struct file *file,
                 void *buf,
                 ssize_t buflen,
                 unsigned long flags)
{
    return 0;
}
ssize_t
fs_file_eof_write(struct file *file,
                  void *buf,
                  ssize_t buflen,
                  unsigned long flags)
{
    return 0;
}

// Keeps the seek head pinned to zero
ssize_t
fs_file_seek_pinned_zero(struct file *file, ssize_t offset, int whence)
{
    return (ssize_t)0;
}

ssize_t
fs_file_seek_any(
        struct file *file,
        ssize_t offset,
        int whence)
{
    switch(whence) {
        case FS_FILE_SEEK_CUR:
            return file->seek_offset + offset;
        case FS_FILE_SEEK_SET:
            return offset;
        case FS_FILE_SEEK_END:
        default:
            return -EINVAL;
    }
}

// Does nothing and returns zero
int
fs_file_nop_flush(struct file *file, unsigned long flags)
{
    return 0;
}

/*
 * Read/Write Using fs_node_read_page and fs_node_write_page implementations
 */

ssize_t
fs_file_paged_read(struct file *file,
                   void *buf,
                   ssize_t buflen,
                   unsigned long flags)
{
    int res;

    if(buflen == 0)
    {
        return -EINVAL;
    }

    struct fs_node *fs_node = fs_path_get_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    order_t order;
    res = fs_node_page_order(fs_node, &order);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    size_t file_size;
    res = fs_node_getattr(fs_node, FS_NODE_ATTR_DATA_SIZE, &file_size);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    // Only reads a page at a time
    uintptr_t seek_loc = file->seek_offset;

    if(seek_loc > file_size)
    {
        fs_node_put(fs_node);
        return -ERANGE;
    }
    if(seek_loc == file_size)
    {
        // EOF
        fs_node_put(fs_node);
        return 0;
    }

    if(seek_loc + buflen > file_size)
    {
        buflen = file_size - seek_loc;
    }

    uintptr_t seek_pfn = seek_loc >> order;
    uintptr_t page_offset = seek_loc & ((1ULL << order) - 1);
    uintptr_t room_left = (1ULL << order) - page_offset;

    struct fs_page *page = fs_node_get_page(fs_node, seek_pfn, 0);
    if(page == NULL)
    {
        fs_node_put(fs_node);
        return -EINVAL;
    }

    ssize_t to_read = buflen < room_left ? buflen : room_left;

    memcpy(buf, ((void *)__va(page->paddr)) + page_offset, to_read);

    res = fs_node_put_page(fs_node, page, 0);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    fs_node_put(fs_node);
    return to_read;
}

ssize_t
fs_file_paged_write(struct file *file,
                    void *buf,
                    ssize_t buflen,
                    unsigned long flags)
{
    int res;

    if(buflen == 0)
    {
        return -EINVAL;
    }

    struct fs_node *fs_node = fs_path_get_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    res = fs_node_paged_write(fs_node,
                              file->seek_offset,
                              buf,
                              buflen,
                              FS_NODE_PAGED_WRITE_MAY_EXTEND);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    fs_node_put(fs_node);
    return buflen;
}

int
fs_file_paged_flush(struct file *file, unsigned long flags)
{
    int res;
    struct fs_node *fs_node = fs_path_get_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }
    res = fs_node_flush_all_fs_pages(fs_node);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }
    fs_node_put(fs_node);
    return 0;
}

// Seek using fs_node_getattr and FS_NODE_ATTR_DATA_SIZE
ssize_t
fs_file_paged_seek(struct file *file, ssize_t offset, int whence)
{
    int res;
    struct fs_node *fs_node = fs_path_get_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    size_t data_size;
    res = fs_node_getattr(fs_node, FS_NODE_ATTR_DATA_SIZE, &data_size);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    fs_node_put(fs_node);

    switch(whence)
    {
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

    if(file->seek_offset > data_size)
    {
        file->seek_offset = data_size;
    }

    return file->seek_offset;
}

int
fs_file_flush_all_fs_pages(struct file *file, unsigned long flags)
{
    int res;
    struct fs_node *fs_node = fs_path_get_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    res = fs_node_flush_all_fs_pages(fs_node);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    fs_node_put(fs_node);
    return 0;
}

int
fs_file_nop_on_open(struct file *file)
{
    return 0;
}
int
fs_file_nop_on_close(struct file *file)
{
    return 0;
}
