
#include <kanawha/fs/file.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/kmalloc.h>

struct file_table;

struct file
{
    atomic_t refs;

    size_t seek_offset;
    size_t dir_offset;

    unsigned long access_flags;
    unsigned long mode_flags;
    unsigned long internal_flags;

    struct fs_path *path;

    struct ptree_node table_node;
    struct file_table *file_table;
};

#define FILE_FILE_OPS_ACCESSOR(__self, __field)                                \
    ({                                                                         \
        struct fs_node *node = fs_path_get_node(__self->path);                 \
        typeof(((struct fs_file_ops *)NULL)->__field) ptr = NULL;              \
        if(node != NULL)                                                       \
        {                                                                      \
            ptr = fs_node_get_file_ops(node)->__field;                         \
            fs_node_put(node); \
        }                                                                      \
        ptr;                                                                   \
    })

DEFINE_OP_LIST_WRAPPERS(FS_FILE_OP_LIST,
                        /* No Qualifiers */,
                        direct_,
                        file,
                        FILE_FILE_OPS_ACCESSOR,
                        SELF_ACCESSOR);

struct file *
fs_file_create(
        struct fs_path *path,
        unsigned long access_flags,
        unsigned long mode_flags,
        unsigned long internal_flags)
{
    struct file *file = kzmalloc(sizeof(struct file), KM_KERNEL);
    if(file == NULL) {
        return NULL;
    }
    fs_path_get(path);
    file->path = path;
    file->mode_flags = mode_flags;
    file->access_flags = access_flags;
    file->internal_flags = internal_flags;

    file->seek_offset = 0;
    file->dir_offset = 0;

    atomic_set_relaxed(&file->refs, 1);

    return file;
}

struct file *
fs_file_clone(
        struct file *file)
{
    struct fs_path *path = fs_file_get_path(file);
    if(path == NULL) {
        return NULL;
    }

    struct file *clone;

    clone = fs_file_create(
            path,
            fs_file_get_access_flags(file),
            fs_file_get_mode_flags(file),
            fs_file_get_internal_flags(file));
    if(clone == NULL) {
        fs_path_put(path);
        return NULL;
    }
    fs_path_put(path);

    fs_file_set_seek_offset(clone, fs_file_get_seek_offset(file));
    fs_file_set_dir_offset(clone, fs_file_get_dir_offset(file));

    return clone;
}

int
fs_file_get(
        struct file *file)
{
    atomic_val_t old = atomic_fetch_inc(&file->refs);
    if(old == 0) {
        return -EINVAL;
    }
    return 0;
}

int
fs_file_put(
        struct file *file)
{
    atomic_val_t old = atomic_fetch_dec(&file->refs);
    if(old == 1) {
        // We need to destroy this file
        if(file->path) {
            fs_path_put(file->path);
            file->path = NULL;
        }
        kfree(file);
    }
    return 0;
}

fd_t
fs_file_get_fd(
        struct file *file)
{
    if(file->file_table == NULL) {
        return -1;
    } else {
        return file->table_node.key;
    }
}
struct file_table *
fs_file_get_file_table(
        struct file *file)
{
    return file->file_table;
}

struct ptree_node *
_fs_file_to_raw_file_table_node(
        struct file *file)
{
    return &file->table_node;
}
struct file *
_fs_file_from_raw_file_table_node(
        struct ptree_node *node)
{
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct file, table_node);
}
int
_fs_file_set_raw_file_table(
        struct file *file,
        struct file_table *table)
{
    file->file_table = table;
    return 0;
}

struct fs_path *
fs_file_get_path(
        struct file *file)
{
    struct fs_path *path = file->path;
    if(path == NULL) {
        return NULL;
    }
    fs_path_get(path);
    return path;
}
struct fs_node *
fs_file_get_node(
        struct file *file)
{
    struct fs_path *path = fs_file_get_path(file);
    if(path == NULL) {
        return NULL;
    }
    struct fs_node *node = fs_path_get_node(path);
    fs_path_put(path);
    return node;
}

size_t
fs_file_get_seek_offset(
        struct file *file)
{
    return file->seek_offset;
}
int
fs_file_set_seek_offset(
        struct file *file,
        size_t value)
{
    file->seek_offset = value;
    return 0;
}
int
fs_file_add_to_seek_offset(
        struct file *file,
        ssize_t value)
{
    file->seek_offset += value;
    return 0;
}

size_t
fs_file_get_dir_offset(
        struct file *file)
{
    return file->dir_offset;
}
int
fs_file_set_dir_offset(
        struct file *file,
        size_t value)
{
    file->dir_offset = value;
    return 0;
}
int
fs_file_add_to_dir_offset(
        struct file *file,
        ssize_t value)
{
    file->dir_offset += value;
    return 0;
}

unsigned long
fs_file_get_internal_flags(
        struct file *file)
{
    return file->internal_flags;
}
int
fs_file_set_internal_flags(
        struct file *file,
        unsigned long to_set)
{
    file->internal_flags |= to_set;
    return 0;
}
int
fs_file_clear_internal_flags(
        struct file *file,
        unsigned long to_clear)
{
    file->internal_flags &= ~to_clear;
    return 0;
}

unsigned long
fs_file_get_mode_flags(
        struct file *file)
{
    return file->mode_flags;
}
int
fs_file_set_mode_flags(
        struct file *file,
        unsigned long to_set)
{
    file->mode_flags |= to_set;
    return 0;
}
int
fs_file_clear_mode_flags(
        struct file *file,
        unsigned long to_clear)
{
    file->mode_flags &= ~to_clear;
    return 0;
}

unsigned long
fs_file_get_access_flags(
        struct file *file)
{
    return file->access_flags;
}
int
fs_file_set_access_flags(
        struct file *file,
        unsigned long to_set)
{
    file->access_flags |= to_set;
    return 0;
}
int
fs_file_clear_access_flags(
        struct file *file,
        unsigned long to_clear)
{
    file->access_flags &= ~to_clear;
    return 0;
}


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
            return fs_file_get_seek_offset(file) + offset;
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

    struct fs_node *fs_node = fs_file_get_node(file);
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
    uintptr_t seek_loc = fs_file_get_seek_offset(file);

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

    struct fs_node *fs_node = fs_file_get_node(file);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    res = fs_node_paged_write(fs_node,
                              fs_file_get_seek_offset(file),
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
    struct fs_node *fs_node = fs_file_get_node(file);
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
    struct fs_node *fs_node = fs_file_get_node(file);
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
    struct fs_node *fs_node = fs_file_get_node(file);
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

