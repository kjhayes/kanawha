
#include <kanawha/sysfs/vfs.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>
#include <kanawha/stddef.h>
#include <kanawha/parse.h>

static struct fs_node_ops vfs_field_node_ops;
static struct fs_file_ops vfs_field_file_ops;

struct vfs_struct_field
{
    struct vfs_node vfs_node;
    size_t inode;

    struct stree_node field_node;
    char *name;

    // Driver State
    void *state;

    // Raw Read/Write Callbacks
    ssize_t(*raw_read)(struct vfs_struct_field *, size_t offset, void *buffer, size_t buflen);
    ssize_t(*raw_write)(struct vfs_struct_field *, size_t offset, void *buffer, size_t buflen);

    // Free this structure
    int(*deallocate)(struct vfs_struct_field *self);
};

static struct fs_node_ops vfs_struct_node_node_ops;
static struct fs_file_ops vfs_struct_node_file_ops;

struct vfs_struct_node
{
    struct vfs_mount *mnt;

    struct vfs_node vfs_node;
    size_t inode;
    char *name;

    spinlock_t field_tree_lock;
    struct stree field_tree;
};

static inline int
__vfs_struct_add_field(
        struct vfs_struct_node *struct_node,
        struct vfs_struct_field *field,
        const char *name,
        void *state,
        ssize_t(*raw_read)(struct vfs_struct_field *, size_t offset, void *buffer, size_t buflen),
        ssize_t(*raw_write)(struct vfs_struct_field *, size_t offset, void *buffer, size_t buflen),
        int(*deallocate)(struct vfs_struct_field *self)
        )
{
    int res;

    field->name = kstrdup(name);
    if(field->name == NULL) {
        return -ENOMEM;
    }

    field->deallocate = deallocate;
    field->raw_read = raw_read;
    field->raw_write = raw_write;
    field->state = state;

    field->vfs_node.fs_node_ops = &vfs_field_node_ops;
    field->vfs_node.fs_file_ops = &vfs_field_file_ops;

    res = vfs_mount_insert_node(
            struct_node->mnt,
            &field->vfs_node,
            &field->inode);
    if(res) {
        kfree(field->name);
        return res;
    }

    res = vfs_node_link(
            &struct_node->vfs_node,
            field->name,
            field->inode);
    if(res) {
        vfs_mount_remove_node(
                struct_node->mnt,
                &field->vfs_node);
        kfree(field->name);
        return res;
    }

    field->field_node.key = field->name;

    spin_lock(&struct_node->field_tree_lock);
    res = stree_insert(
            &struct_node->field_tree,
            &field->field_node);
    spin_unlock(&struct_node->field_tree_lock);
    if(res) {
        vfs_node_unlink(
                &struct_node->vfs_node,
                field->name);
        vfs_mount_remove_node(
                struct_node->mnt,
                &field->vfs_node);
        kfree(field->name);
        return res;
    }

    return 0;
}

int
vfs_struct_node_destroy_field(
        struct vfs_struct_node *node,
        const char *name)
{
    int res;

    struct vfs_struct_field *field = NULL;

    spin_lock(&node->field_tree_lock);
    {
    struct stree_node *snode = stree_get(
            &node->field_tree,
            name);
    if(snode == NULL) {
        spin_unlock(&node->field_tree_lock);
        return -ENXIO;
    }
    field = container_of(snode, struct vfs_struct_field, field_node);

    struct stree_node *rem = stree_remove(&node->field_tree, field->name);
    DEBUG_ASSERT(rem == snode);
    }
    spin_unlock(&node->field_tree_lock);

    res = vfs_node_unlink(
            &node->vfs_node,
            field->name);
    ASSERT(res == 0);

    res = vfs_mount_remove_node(
            node->mnt,
            &field->vfs_node);
    ASSERT(res == 0);

    kfree(field->name);

    DEBUG_ASSERT(KERNEL_ADDR(field->deallocate));

    // Remove the backing memory of the field
    res = (field->deallocate)(field);
    WARN_ASSERT(res);

    return 0;
}

static ssize_t
vfs_field_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EUNIMPL;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -EUNIMPL;
    }

    struct vfs_struct_field *field = container_of(fs_node->backing.priv_state, struct vfs_struct_field, vfs_node);

    return (*field->raw_read)(field, file->seek_offset, buffer, buflen);
}

static ssize_t
vfs_field_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    if(flags & FS_FILE_WRITE_NON_BLOCKING) {
        return -EUNIMPL;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -EUNIMPL;
    }

    struct vfs_struct_field *field = container_of(fs_node->backing.priv_state, struct vfs_struct_field, vfs_node);

    return (*field->raw_write)(field, file->seek_offset, buffer, buflen);
}

static struct fs_node_ops vfs_field_node_ops =
{

    .flush = fs_node_flush_nop,

    .setattr = fs_node_cannot_setattr,
    .getattr = fs_node_cannot_getattr,
    .lookup = fs_node_cannot_lookup, 
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
};
static struct fs_file_ops vfs_field_file_ops =
{
    .read = vfs_field_fs_file_read,
    .write = vfs_field_fs_file_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

struct vfs_struct_node *
vfs_create_struct_node(
        struct vfs_mount *mnt,
        const char *name)
{
    int res;

    struct vfs_struct_node *node;
    node = kmalloc(sizeof(struct vfs_struct_node), KM_KERNEL);
    if(node == NULL) {
        return NULL;
    }

    node->mnt = mnt;

    node->vfs_node.fs_node_ops = &vfs_struct_node_node_ops;
    node->vfs_node.fs_file_ops = &vfs_struct_node_file_ops;

    spinlock_init(&node->field_tree_lock);
    stree_init(&node->field_tree);

    node->name = kstrdup(name);
    if(node->name == NULL) {
        kfree(node);
        return NULL;
    }

    res = vfs_mount_insert_node(
            mnt,
            &node->vfs_node,
            &node->inode);
    if(res) {
        kfree(node->name);
        kfree(node);
        return NULL;
    }

    res = vfs_mount_link_root(
            mnt,
            name,
            node->inode);
    if(res) {
        vfs_mount_remove_node(
                mnt,
                &node->vfs_node);
        kfree(node->name);
        kfree(node);
        return NULL;
    }

    return node;
}

int
vfs_destroy_struct_node(
        struct vfs_struct_node *node)
{
    int res;
    res = vfs_mount_unlink_root(
            node->mnt,
            node->name);
    if(res) {
        return res;
    }

    res = vfs_mount_remove_node(node->mnt, &node->vfs_node);
    if(res) {
        return res;
    }

    kfree(node->name);
    kfree(node);
    return 0;
}

static struct fs_node_ops vfs_struct_node_node_ops =
{
    .flush = fs_node_flush_nop,
    .lookup = vfs_dir_lookup,

    .setattr = fs_node_cannot_setattr,
    .getattr = fs_node_cannot_getattr,
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
};
static struct fs_file_ops vfs_struct_node_file_ops =
{
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,

    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .seek = fs_file_cannot_seek,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,
};


struct vfs_struct_unsigned_long_field
{
    struct vfs_struct_field vfs_field;
    int(*read)(unsigned long *out, void *state); 
    int(*write)(unsigned long in, void *state);
};

static int
__vfs_struct_deallocate_unsigned_long_field(
        struct vfs_struct_field *gen_field)
{
    struct vfs_struct_unsigned_long_field *field;
    field = container_of(gen_field, struct vfs_struct_unsigned_long_field, vfs_field);
    kfree(field);
    return 0;
}

static ssize_t
__vfs_struct_unsigned_long_field_raw_write(
        struct vfs_struct_field *gen_field,
        size_t offset,
        void *buffer,
        size_t buflen)
{
    int res;

    struct vfs_struct_unsigned_long_field *field;
    field = container_of(gen_field, struct vfs_struct_unsigned_long_field, vfs_field);
 
    if(field->write == NULL) {
        return -EINVAL;
    }

    if(offset != 0) {
        return 0;
    }

    char str_buf[buflen+1];
    memcpy(str_buf, buffer, buflen);
    str_buf[buflen] = '\0';

    unsigned long val = parse_unsigned_long(str_buf, 0);

    res = (*field->write)(val, field->vfs_field.state);
    if(res == 0) {
        return buflen;
    } else if(res < 0) {
        return res;
    } else {
        return -EINVAL;
    }
}

static ssize_t
__vfs_struct_unsigned_long_field_raw_read(
        struct vfs_struct_field *gen_field,
        size_t offset,
        void *buffer,
        size_t buflen)
{
    int res;

    struct vfs_struct_unsigned_long_field *field;
    field = container_of(gen_field, struct vfs_struct_unsigned_long_field, vfs_field);

    if(field->read == NULL) {
        return -EINVAL;
    }

    if(offset != 0) {
        return 0;
    }

    unsigned long val;

    res = (*field->read)(&val, field->vfs_field.state);
    if(res != 0) {
        if(res < 0) {
            return res;
        } else {
            return -EINVAL;
        }
    }

    snprintk(buffer, buflen, "%lu", val);

    size_t len = strnlen(buffer, buflen);

    return len;
}
int
vfs_struct_node_add_unsigned_long_field(
        struct vfs_struct_node *node,
        const char *name,
        void *state,
        int(*read)(unsigned long *out, void *state),
        int(*write)(unsigned long in, void *state)
        )
{
    int res;

    struct vfs_struct_unsigned_long_field *field;

    field = kmalloc(sizeof(*field), KM_KERNEL);
    if(field == NULL) {
        return -ENOMEM;
    }

    field->read = read;
    field->write = write;

    res = __vfs_struct_add_field(
            node,
            &field->vfs_field,
            name,
            state,
            __vfs_struct_unsigned_long_field_raw_read,
            __vfs_struct_unsigned_long_field_raw_write,
            __vfs_struct_deallocate_unsigned_long_field);
    if(res) {
        kfree(field);
        return res;
    }

    return 0;
}

// buffer field

struct vfs_struct_buffer_field
{
    struct vfs_struct_field vfs_field;
    ssize_t(*read)(size_t offset, char *buf_out, size_t len, void *state); 
    ssize_t(*write)(size_t offset, char *buf_in, size_t len, void *state);
};

static int
__vfs_struct_deallocate_buffer_field(
        struct vfs_struct_field *gen_field)
{
    struct vfs_struct_buffer_field *field;
    field = container_of(gen_field, struct vfs_struct_buffer_field, vfs_field);
    kfree(field);
    return 0;
}

static ssize_t
__vfs_struct_buffer_field_raw_write(
        struct vfs_struct_field *gen_field,
        size_t offset,
        void *buffer,
        size_t buflen)
{
    int res;

    struct vfs_struct_buffer_field *field;
    field = container_of(gen_field, struct vfs_struct_buffer_field, vfs_field);
 
    if(field->write == NULL) {
        return -EINVAL;
    }

    return (field->write)(offset, buffer, buflen, field->vfs_field.state);
}

static ssize_t
__vfs_struct_buffer_field_raw_read(
        struct vfs_struct_field *gen_field,
        size_t offset,
        void *buffer,
        size_t buflen)
{
    int res;

    struct vfs_struct_buffer_field *field;
    field = container_of(gen_field, struct vfs_struct_buffer_field, vfs_field);

    if(field->read == NULL) {
        return -EINVAL;
    }

    return (*field->read)(offset, buffer, buflen, field->vfs_field.state);
}

int
vfs_struct_node_add_buffer_field(
        struct vfs_struct_node *node,
        const char *name,
        void *state,
        ssize_t(*read)(size_t offset, char *buf_out, size_t len, void *state),
        ssize_t(*write)(size_t offset, char *buf_in, size_t len, void *state)
        )
{
    int res;

    struct vfs_struct_buffer_field *field;

    field = kmalloc(sizeof(*field), KM_KERNEL);
    if(field == NULL) {
        return -ENOMEM;
    }

    field->read = read;
    field->write = write;

    res = __vfs_struct_add_field(
            node,
            &field->vfs_field,
            name,
            state,
            __vfs_struct_buffer_field_raw_read,
            __vfs_struct_buffer_field_raw_write,
            __vfs_struct_deallocate_buffer_field);
    if(res) {
        kfree(field);
        return res;
    }

    return 0;
}

