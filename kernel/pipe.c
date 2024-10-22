
#include <kanawha/pipe.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/ptree.h>
#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>
#include <kanawha/process.h>
#include <kanawha/usermode.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/flat.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>

/*
 * At this point, PipeFS is a "pseudo" filesystem,
 * which cannot be properly mounted,
 * and really just allows creation of anonymous pipes,
 *
 * you can try to load any "inode" and the mount
 * will just create a new pipe, so if the fs subsystem
 * every tried to "load" the same node twice without unloading,
 * then we would leak memory
 */

#define DEFAULT_PIPE_BUFSIZE PAGE_SIZE_4KB

static DECLARE_SPINLOCK(pipe_tree_lock);
static DECLARE_PTREE(pipe_tree);

static struct fs_node_ops
pipe_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .flush = fs_node_cannot_flush,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static ssize_t 
pipe_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount)
{
    dprintk("pipefs read: amount=%p\n", amount);
    if(amount == 0) {
        return 0;
    }

    struct pipe *pipe =
        container_of(file->path->fs_node, struct pipe, fs_node);

    DEBUG_ASSERT(KERNEL_ADDR(pipe));
    DEBUG_ASSERT(KERNEL_ADDR(pipe->buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(pipe->buflen > pipe->head);
    DEBUG_ASSERT(pipe->buflen > pipe->tail);

    ssize_t read = 0;
    spin_lock(&pipe->lock);

    while(read <= 0) {
        if(pipe->head != pipe->tail) {
            // The buffer is non-empty
            *(uint8_t*)buffer = ((uint8_t*)pipe->buffer)[pipe->tail];
            pipe->tail = (pipe->tail + 1) % pipe->buflen;
            read += 1;
            break;
        } else {
            spin_unlock(&pipe->lock);
            dprintk("pipe_fs_read (SLEEPING)\n");
            wait_on(&pipe->read_queue);
            spin_lock(&pipe->lock);
        }
    }

    spin_unlock(&pipe->lock);
    if(read > 0) {
        wake_all(&pipe->write_queue);
    }
    return read;
}

static ssize_t 
pipe_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount)
{
    if(amount == 0) {
        return 0;
    }

    struct pipe *pipe =
        container_of(file->path->fs_node, struct pipe, fs_node);

    DEBUG_ASSERT(KERNEL_ADDR(pipe));
    DEBUG_ASSERT(KERNEL_ADDR(pipe->buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(pipe->buflen > pipe->head);
    DEBUG_ASSERT(pipe->buflen > pipe->tail);

    ssize_t written = 0;
    spin_lock(&pipe->lock);

    // TODO: Allow writes of more than a byte at a time
    while(written <= 0) {
        if(((pipe->head+1)%pipe->buflen) != pipe->tail) {
            // The buffer still has room
            ((uint8_t*)pipe->buffer)[pipe->head] = *(uint8_t*)buffer;
            pipe->head = (pipe->head + 1) % pipe->buflen;
            written += 1;
            break;
        } else {
            spin_unlock(&pipe->lock);
            dprintk("pipe_fs_write (SLEEPING)\n");
            wait_on(&pipe->write_queue);
            spin_lock(&pipe->lock);
        }
    }

    spin_unlock(&pipe->lock);
    if(written > 0) {
        wake_all(&pipe->read_queue);
    }
    return written;
}

static struct fs_file_ops
pipe_fs_file_ops =
{
    .read = pipe_fs_file_read,
    .write = pipe_fs_file_write,

    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,

    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
pipe_fs_root_index(struct fs_mount *mnt, size_t *index)
{
    // Cannot mount pipefs the traditional way,
    // so there is not need for a "root" directory
    return -EINVAL;
}

static struct fs_node *
pipe_fs_mount_load_node(
        struct fs_mount *mnt,
        size_t index)
{
    int res;

    // We assume the upper level will never try to load a node
    // which already exists, so we can just let them give us a
    // unique index (TODO: This might not be a safe assumption long term)

    struct pipe *pipe = kmalloc(sizeof(struct pipe));
    if(pipe == NULL) {
        return NULL;
    }

    pipe->buflen = DEFAULT_PIPE_BUFSIZE;
    pipe->buffer = kmalloc(pipe->buflen);
    if(pipe->buffer == NULL) {
        kfree(pipe);
        return NULL;
    }
    pipe->head = 0;
    pipe->tail = 0;
    spinlock_init(&pipe->lock);

    pipe->fs_node.node_ops = &pipe_fs_node_ops;
    pipe->fs_node.file_ops = &pipe_fs_file_ops;

    res = waitqueue_init(&pipe->read_queue);
    if(res) {
        kfree(pipe);
        return NULL;
    }

    res = waitqueue_init(&pipe->write_queue);
    if(res) {
        waitqueue_disable(&pipe->read_queue);
        wake_all(&pipe->read_queue);
        waitqueue_deinit(&pipe->read_queue);
        kfree(pipe);
        return NULL;
    }

    return &pipe->fs_node;
}

static int
pipe_fs_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    struct pipe *pipe =
        container_of(node, struct pipe, fs_node);

    waitqueue_disable(&pipe->read_queue);
    wake_all(&pipe->read_queue);
    waitqueue_deinit(&pipe->read_queue);

    waitqueue_disable(&pipe->write_queue);
    wake_all(&pipe->write_queue);
    waitqueue_deinit(&pipe->write_queue);

    kfree(pipe->buffer);
    kfree(pipe);

    return 0;
}

static struct fs_mount_ops
pipe_fs_mount_ops =
{
    .root_index = pipe_fs_root_index,

    .load_node = pipe_fs_mount_load_node,
    .unload_node = pipe_fs_mount_unload_node,
};

static struct fs_mount pipe_fs_mount;

static int
pipefs_init(void)
{
    return init_fs_mount_struct(
            &pipe_fs_mount,
            &pipe_fs_mount_ops);
}
declare_init_desc(fs, pipefs_init, "Creating PipeFS");

struct fs_node *
pipe_fs_get_anon_pipe(void)
{
    return fs_mount_get_node(
            &pipe_fs_mount,
            0);
}

